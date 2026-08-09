using Microsoft.EntityFrameworkCore;
using SoftLicence.Server.Data;

namespace SoftLicence.Server.Services;

public sealed class SecurityCanaryAnalyticsService
{
    private const int MaxTake = 200;
    private const int MaxRows = 5000;
    private readonly IDbContextFactory<LicenseDbContext> _dbFactory;

    public SecurityCanaryAnalyticsService(IDbContextFactory<LicenseDbContext> dbFactory)
    {
        _dbFactory = dbFactory;
    }

    public async Task<SecurityCanaryListResponse> ListForProductIdAsync(
        Guid productId,
        DateTime? fromUtc,
        DateTime? toUtc,
        string? trigger,
        int? severity,
        string? hardwareId,
        string? machine,
        string? user,
        string? clientIp,
        string? version,
        bool? isBanned,
        int take,
        int offset,
        CancellationToken cancellationToken = default)
    {
        take = Math.Clamp(take, 1, MaxTake);
        offset = Math.Max(0, offset);
        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        var productScopeIds = await ProductScopeResolver.ResolveProductScopeIdsAsync(db, productId, cancellationToken);

        var query = db.CanaryAlerts.AsNoTracking()
            .Where(a => a.ProductId.HasValue && productScopeIds.Contains(a.ProductId.Value));

        if (fromUtc.HasValue) query = query.Where(a => a.ReceivedAt >= fromUtc.Value);
        if (toUtc.HasValue) query = query.Where(a => a.ReceivedAt <= toUtc.Value);
        if (!string.IsNullOrWhiteSpace(trigger))
        {
            var value = trigger.Trim().ToUpper();
            query = query.Where(a => a.Trigger.ToUpper().Contains(value));
        }
        if (severity.HasValue) query = query.Where(a => a.Severity == severity.Value);
        if (!string.IsNullOrWhiteSpace(hardwareId))
        {
            var value = hardwareId.Trim().ToUpper();
            query = query.Where(a => a.HardwareId.ToUpper().Contains(value));
        }
        if (!string.IsNullOrWhiteSpace(machine))
        {
            var value = machine.Trim().ToUpper();
            query = query.Where(a => a.MachineName != null && a.MachineName.ToUpper().Contains(value));
        }
        if (!string.IsNullOrWhiteSpace(user))
        {
            var value = user.Trim().ToUpper();
            query = query.Where(a => a.UserName != null && a.UserName.ToUpper().Contains(value));
        }
        if (!string.IsNullOrWhiteSpace(clientIp))
        {
            var value = clientIp.Trim();
            query = query.Where(a => a.ClientIp == value);
        }
        if (!string.IsNullOrWhiteSpace(version))
        {
            var value = version.Trim();
            query = query.Where(a => a.AppVersion == value);
        }

        var rows = await query
            .OrderByDescending(a => a.LastSeenAt ?? a.ReceivedAt)
            .Take(MaxRows)
            .ToListAsync(cancellationToken);

        var incidentQuery = db.SecurityIncidents.AsNoTracking()
            .Include(i => i.Evidence)
            .Where(i => productScopeIds.Contains(i.ProductId));

        if (fromUtc.HasValue) incidentQuery = incidentQuery.Where(i => i.LastSeenUtc >= fromUtc.Value);
        if (toUtc.HasValue) incidentQuery = incidentQuery.Where(i => i.FirstSeenUtc <= toUtc.Value);
        if (!string.IsNullOrWhiteSpace(trigger))
        {
            var value = trigger.Trim().ToUpper();
            incidentQuery = incidentQuery.Where(i => i.Family.ToUpper().Contains(value));
        }
        if (severity.HasValue) incidentQuery = incidentQuery.Where(i => i.Severity == severity.Value);
        if (!string.IsNullOrWhiteSpace(hardwareId))
        {
            var value = hardwareId.Trim().ToUpper();
            incidentQuery = incidentQuery.Where(i => i.HardwareId.ToUpper().Contains(value));
        }
        if (!string.IsNullOrWhiteSpace(machine) || !string.IsNullOrWhiteSpace(user))
            incidentQuery = incidentQuery.Where(_ => false);
        if (!string.IsNullOrWhiteSpace(clientIp))
        {
            var value = clientIp.Trim();
            incidentQuery = incidentQuery.Where(i => i.ClientIp == value);
        }
        if (!string.IsNullOrWhiteSpace(version))
        {
            var value = version.Trim();
            incidentQuery = incidentQuery.Where(i => i.Version == value);
        }

        var incidents = await incidentQuery
            .OrderByDescending(i => i.LastSeenUtc)
            .Take(MaxRows)
            .ToListAsync(cancellationToken);

        var hwids = rows.Select(a => a.HardwareId)
            .Concat(incidents.Select(i => i.HardwareId))
            .Select(h => h.ToUpperInvariant())
            .Distinct(StringComparer.Ordinal)
            .ToList();
        var bannedHwids = hwids.Count == 0
            ? new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            : (await db.BannedHardwareIds.AsNoTracking()
                .Where(b => b.IsActive
                    && (b.ExpiresAt == null || b.ExpiresAt > DateTime.UtcNow)
                    && (b.ProductId == null || productScopeIds.Contains(b.ProductId.Value))
                    && hwids.Contains(b.HardwareId.ToUpper()))
                .Select(b => b.HardwareId)
                .ToListAsync(cancellationToken))
                .ToHashSet(StringComparer.OrdinalIgnoreCase);

        var grouped = rows
            .GroupBy(a => new
            {
                HardwareId = a.HardwareId.ToUpperInvariant(),
                Trigger = a.Trigger.ToUpperInvariant(),
                a.Details
            })
            .Select(g =>
            {
                var latest = g.OrderByDescending(a => a.LastSeenAt ?? a.ReceivedAt).First();
                var firstSeen = g.Min(a => a.ReceivedAt);
                var lastSeen = g.Max(a => a.LastSeenAt ?? a.ReceivedAt);
                return new SecurityCanarySummary
                {
                    AlertId = latest.Id,
                    SourceKind = "client_canary",
                    ProductId = latest.ProductId,
                    HardwareId = latest.HardwareId,
                    MachineName = latest.MachineName,
                    UserName = latest.UserName,
                    ClientIp = latest.ClientIp,
                    Version = latest.AppVersion,
                    Trigger = latest.Trigger,
                    Severity = latest.Severity,
                    FirstSeenUtc = firstSeen,
                    LastSeenUtc = lastSeen,
                    RepeatCount = g.Sum(a => a.RepeatCount),
                    PingCount = g.Sum(a => a.RepeatCount + 1),
                    IsHardwareBanned = bannedHwids.Contains(latest.HardwareId),
                    ServerAction = latest.ServerAction
                };
            })
            .ToList();

        grouped.AddRange(incidents.Select(i => new SecurityCanarySummary
        {
            AlertId = i.Id,
            SourceKind = "server_incident",
            ProductId = i.ProductId,
            HardwareId = i.HardwareId,
            ClientIp = i.ClientIp,
            Version = i.Version,
            Trigger = i.Family,
            Severity = i.Severity,
            FirstSeenUtc = i.FirstSeenUtc,
            LastSeenUtc = i.LastSeenUtc,
            RepeatCount = i.OccurrenceCount,
            PingCount = i.OccurrenceCount,
            IsHardwareBanned = bannedHwids.Contains(i.HardwareId),
            ServerAction = i.IsHardwareBanned ? "Banned" : "Observed",
            EvidenceCount = i.Evidence.Count
        }));

        if (isBanned.HasValue)
            grouped = grouped.Where(a => a.IsHardwareBanned == isBanned.Value).ToList();

        grouped = grouped.OrderByDescending(a => a.LastSeenUtc).ToList();

        return new SecurityCanaryListResponse
        {
            GeneratedAtUtc = DateTime.UtcNow,
            GroupsMatched = grouped.Count,
            GroupsReturned = Math.Min(take, Math.Max(0, grouped.Count - offset)),
            Take = take,
            Offset = offset,
            Alerts = grouped.Skip(offset).Take(take).ToList()
        };
    }

    public async Task<SecurityCanaryDetailsResponse?> GetDetailsForProductIdAsync(
        Guid productId,
        Guid alertId,
        CancellationToken cancellationToken = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        var productScopeIds = await ProductScopeResolver.ResolveProductScopeIdsAsync(db, productId, cancellationToken);
        var alert = await db.CanaryAlerts.AsNoTracking()
            .Include(a => a.Product)
            .SingleOrDefaultAsync(a => a.Id == alertId
                && a.ProductId.HasValue
                && productScopeIds.Contains(a.ProductId.Value), cancellationToken);
        if (alert == null)
            return await GetIncidentDetailsAsync(db, productScopeIds, alertId, cancellationToken);

        var bans = await db.BannedHardwareIds.AsNoTracking()
            .Where(b => b.HardwareId == alert.HardwareId
                && (b.ProductId == null || productScopeIds.Contains(b.ProductId.Value)))
            .OrderByDescending(b => b.BannedAt)
            .Take(25)
            .Select(b => new SecurityCanaryAssociatedBan
            {
                BanId = b.Id,
                IsActive = b.IsActive,
                BannedAtUtc = b.BannedAt,
                ExpiresAtUtc = b.ExpiresAt,
                Category = b.BanCategory,
                Reason = b.Reason
            })
            .ToListAsync(cancellationToken);

        return new SecurityCanaryDetailsResponse
        {
            AlertId = alert.Id,
            SourceKind = "client_canary",
            ProductId = alert.ProductId,
            ProductName = alert.Product?.Name,
            HardwareId = alert.HardwareId,
            MachineName = alert.MachineName,
            UserName = alert.UserName,
            ClientIp = alert.ClientIp,
            Version = alert.AppVersion,
            Trigger = alert.Trigger,
            Details = alert.Details,
            Severity = alert.Severity,
            FirstSeenUtc = alert.ReceivedAt,
            LastSeenUtc = alert.LastSeenAt ?? alert.ReceivedAt,
            RepeatCount = alert.RepeatCount,
            PingCount = alert.RepeatCount + 1,
            OsVersion = alert.OsVersion,
            BuildConfiguration = alert.BuildConfiguration,
            BaseDirectory = alert.BaseDirectory,
            ProcessPath = alert.ProcessPath,
            AssemblyLocation = alert.AssemblyLocation,
            IsLocalDevBuild = alert.IsLocalDevBuild,
            LocalDevBuildReason = alert.LocalDevBuildReason,
            BinaryFingerprintsJson = alert.BinaryFingerprintsJson,
            ServerAction = alert.ServerAction,
            HardwareBans = bans
        };
    }

    private static async Task<SecurityCanaryDetailsResponse?> GetIncidentDetailsAsync(
        LicenseDbContext db,
        IReadOnlyCollection<Guid> productScopeIds,
        Guid incidentId,
        CancellationToken cancellationToken)
    {
        var incident = await db.SecurityIncidents.AsNoTracking()
            .Include(i => i.Product)
            .Include(i => i.Evidence)
            .SingleOrDefaultAsync(i => i.Id == incidentId && productScopeIds.Contains(i.ProductId), cancellationToken);
        if (incident == null) return null;

        var hardwareBans = await db.BannedHardwareIds.AsNoTracking()
            .Where(b => b.HardwareId.ToUpper() == incident.HardwareId
                && (b.ProductId == null || productScopeIds.Contains(b.ProductId.Value)))
            .OrderByDescending(b => b.BannedAt)
            .Take(25)
            .Select(b => new SecurityCanaryAssociatedBan
            {
                BanId = b.Id,
                IsActive = b.IsActive,
                BannedAtUtc = b.BannedAt,
                ExpiresAtUtc = b.ExpiresAt,
                Category = b.BanCategory,
                Reason = b.Reason
            })
            .ToListAsync(cancellationToken);

        var evidenceKeys = incident.Evidence
            .Select(e => $"{e.ComponentType}:{e.ComponentHash}")
            .ToHashSet(StringComparer.Ordinal);
        var hashes = incident.Evidence.Select(e => e.ComponentHash).Distinct().ToList();
        var componentBanRows = hashes.Count == 0
            ? []
            : await db.BannedComponents.AsNoTracking()
                .Where(b => hashes.Contains(b.ComponentHash.ToUpper())
                    && (b.ProductId == null || productScopeIds.Contains(b.ProductId.Value)))
                .OrderByDescending(b => b.BannedAt)
                .Take(500)
                .ToListAsync(cancellationToken);
        var componentBans = componentBanRows
            .Where(b => evidenceKeys.Contains($"{b.ComponentType.ToUpperInvariant()}:{b.ComponentHash.ToUpperInvariant()}"))
            .Take(100)
            .Select(b => new SecurityCanaryAssociatedComponentBan
            {
                BanId = b.Id,
                ComponentType = b.ComponentType,
                ComponentHash = b.ComponentHash,
                IsActive = b.IsActive,
                BannedAtUtc = b.BannedAt,
                ExpiresAtUtc = b.ExpiresAt,
                Reason = b.Reason
            })
            .ToList();

        return new SecurityCanaryDetailsResponse
        {
            AlertId = incident.Id,
            SourceKind = "server_incident",
            ProductId = incident.ProductId,
            ProductName = incident.Product?.Name,
            HardwareId = incident.HardwareId,
            ClientIp = incident.ClientIp,
            Version = incident.Version,
            Trigger = incident.Family,
            Severity = incident.Severity,
            FirstSeenUtc = incident.FirstSeenUtc,
            LastSeenUtc = incident.LastSeenUtc,
            RepeatCount = incident.OccurrenceCount,
            PingCount = incident.OccurrenceCount,
            ServerAction = incident.IsHardwareBanned ? "Banned" : "Observed",
            InitialNotificationSentAtUtc = incident.InitialNotificationSentAtUtc,
            Evidence = incident.Evidence
                .OrderBy(e => e.ComponentType, StringComparer.Ordinal)
                .ThenBy(e => e.ComponentHash, StringComparer.Ordinal)
                .Select(e => new SecurityCanaryIncidentEvidence
                {
                    ComponentType = e.ComponentType,
                    ComponentHash = e.ComponentHash,
                    FirstSeenUtc = e.FirstSeenUtc,
                    LastSeenUtc = e.LastSeenUtc,
                    OccurrenceCount = e.OccurrenceCount
                })
                .ToList(),
            HardwareBans = hardwareBans,
            ComponentBans = componentBans
        };
    }
}

public sealed class SecurityCanaryListResponse
{
    public DateTime GeneratedAtUtc { get; set; }
    public int GroupsMatched { get; set; }
    public int GroupsReturned { get; set; }
    public int Take { get; set; }
    public int Offset { get; set; }
    public List<SecurityCanarySummary> Alerts { get; set; } = [];
}

public sealed class SecurityCanarySummary
{
    public Guid AlertId { get; set; }
    public string SourceKind { get; set; } = "client_canary";
    public Guid? ProductId { get; set; }
    public string HardwareId { get; set; } = "";
    public string? MachineName { get; set; }
    public string? UserName { get; set; }
    public string? ClientIp { get; set; }
    public string? Version { get; set; }
    public string Trigger { get; set; } = "";
    public int Severity { get; set; }
    public DateTime FirstSeenUtc { get; set; }
    public DateTime LastSeenUtc { get; set; }
    public int RepeatCount { get; set; }
    public int PingCount { get; set; }
    public bool IsHardwareBanned { get; set; }
    public string? ServerAction { get; set; }
    public int EvidenceCount { get; set; }
}

public sealed class SecurityCanaryDetailsResponse
{
    public Guid AlertId { get; set; }
    public string SourceKind { get; set; } = "client_canary";
    public Guid? ProductId { get; set; }
    public string? ProductName { get; set; }
    public string HardwareId { get; set; } = "";
    public string? MachineName { get; set; }
    public string? UserName { get; set; }
    public string? ClientIp { get; set; }
    public string? Version { get; set; }
    public string Trigger { get; set; } = "";
    public string? Details { get; set; }
    public int Severity { get; set; }
    public DateTime FirstSeenUtc { get; set; }
    public DateTime LastSeenUtc { get; set; }
    public int RepeatCount { get; set; }
    public int PingCount { get; set; }
    public string? OsVersion { get; set; }
    public string? BuildConfiguration { get; set; }
    public string? BaseDirectory { get; set; }
    public string? ProcessPath { get; set; }
    public string? AssemblyLocation { get; set; }
    public bool? IsLocalDevBuild { get; set; }
    public string? LocalDevBuildReason { get; set; }
    public string? BinaryFingerprintsJson { get; set; }
    public string? ServerAction { get; set; }
    public DateTime? InitialNotificationSentAtUtc { get; set; }
    public List<SecurityCanaryIncidentEvidence> Evidence { get; set; } = [];
    public List<SecurityCanaryAssociatedBan> HardwareBans { get; set; } = [];
    public List<SecurityCanaryAssociatedComponentBan> ComponentBans { get; set; } = [];
}

public sealed class SecurityCanaryIncidentEvidence
{
    public string ComponentType { get; set; } = "";
    public string ComponentHash { get; set; } = "";
    public DateTime FirstSeenUtc { get; set; }
    public DateTime LastSeenUtc { get; set; }
    public int OccurrenceCount { get; set; }
}

public sealed class SecurityCanaryAssociatedComponentBan
{
    public Guid BanId { get; set; }
    public string ComponentType { get; set; } = "";
    public string ComponentHash { get; set; } = "";
    public bool IsActive { get; set; }
    public DateTime BannedAtUtc { get; set; }
    public DateTime? ExpiresAtUtc { get; set; }
    public string Reason { get; set; } = "";
}

public sealed class SecurityCanaryAssociatedBan
{
    public Guid BanId { get; set; }
    public bool IsActive { get; set; }
    public DateTime BannedAtUtc { get; set; }
    public DateTime? ExpiresAtUtc { get; set; }
    public string? Category { get; set; }
    public string Reason { get; set; } = "";
}
