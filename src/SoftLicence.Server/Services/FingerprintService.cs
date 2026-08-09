using Microsoft.EntityFrameworkCore;
using SoftLicence.Server.Data;
using System.Security.Cryptography;
using System.Text;

namespace SoftLicence.Server.Services;

public class FingerprintService
{
    private readonly IDbContextFactory<LicenseDbContext> _dbFactory;
    private readonly ILogger<FingerprintService> _logger;
    private readonly SettingsService _settings;

    // Hashes SHA256 des valeurs WMI génériques connues (renvoyées sur du matériel non configuré / VMs).
    // Un composant dont le hash est dans cette liste est ignoré lors des comparaisons de cluster.
    private static readonly HashSet<string> _genericHashes = BuildGenericHashes();

    private static HashSet<string> BuildGenericHashes()
    {
        var genericValues = new[]
        {
            "To Be Filled By O.E.M.",
            "Default string",
            "Default String",
            "None",
            "00000000",
            "Not Specified",
            "Chassis Serial Number",
            "UNKNOWN",
            "NON-WINDOWS",
            "System Product Name",
            "System Serial Number",
            "System Version",
            "Base Board Serial Number",
            "0",
            " ",
            "",
        };

        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var v in genericValues)
        {
            var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(v));
            set.Add(BitConverter.ToString(bytes).Replace("-", "").ToLowerInvariant());
        }
        return set;
    }

    public FingerprintService(IDbContextFactory<LicenseDbContext> dbFactory, ILogger<FingerprintService> logger, SettingsService settings)
    {
        _dbFactory = dbFactory;
        _logger = logger;
        _settings = settings;
    }

    public async Task UpsertFingerprintAsync(string hardwareId, Dictionary<string, string> fingerprints)
    {
        if (string.IsNullOrEmpty(hardwareId) || fingerprints.Count == 0) return;

        using var db = await _dbFactory.CreateDbContextAsync();
        var existing = await db.HardwareFingerprints.FirstOrDefaultAsync(f => f.HardwareId == hardwareId);

        fingerprints.TryGetValue("FP_CPU", out var cpu);
        fingerprints.TryGetValue("FP_MB", out var mb);
        fingerprints.TryGetValue("FP_BIOS", out var bios);
        fingerprints.TryGetValue("FP_DISK", out var disk);
        fingerprints.TryGetValue("FP_HOST", out var host);

        if (existing != null)
        {
            existing.LastSeenAt = DateTime.UtcNow;
            if (cpu != null) existing.CpuHash = cpu;
            if (mb != null) existing.MotherboardHash = mb;
            if (bios != null) existing.BiosHash = bios;
            if (disk != null) existing.DiskHash = disk;
            if (host != null) existing.HostHash = host;
        }
        else
        {
            db.HardwareFingerprints.Add(new HardwareFingerprint
            {
                HardwareId = hardwareId,
                CpuHash = cpu,
                MotherboardHash = mb,
                BiosHash = bios,
                DiskHash = disk,
                HostHash = host
            });
        }

        await db.SaveChangesAsync();
    }

    public async Task<List<RelatedHwid>> FindRelatedHwidsAsync(string hardwareId)
    {
        using var db = await _dbFactory.CreateDbContextAsync();
        var source = await db.HardwareFingerprints.AsNoTracking().FirstOrDefaultAsync(f => f.HardwareId == hardwareId);
        if (source == null) return new List<RelatedHwid>();

        var threshold = int.Parse(await _settings.GetSettingAsync("FingerprintMatchThreshold", "3") ?? "3");

        var all = await db.HardwareFingerprints.AsNoTracking()
            .Where(f => f.HardwareId != hardwareId)
            .ToListAsync();

        var results = new List<RelatedHwid>();
        foreach (var f in all)
        {
            int matches = CountMatches(source, f);
            if (matches >= threshold)
            {
                results.Add(new RelatedHwid
                {
                    HardwareId = f.HardwareId,
                    MatchCount = matches,
                    ClusterId = f.ClusterId,
                    LastSeenAt = f.LastSeenAt
                });
            }
        }

        return results.OrderByDescending(r => r.MatchCount).ToList();
    }

    public async Task RunClusteringAsync()
    {
        using var db = await _dbFactory.CreateDbContextAsync();
        var threshold = int.Parse(await _settings.GetSettingAsync("FingerprintMatchThreshold", "3") ?? "3");

        var all = await db.HardwareFingerprints.ToListAsync();

        // Reset clusters
        foreach (var f in all) f.ClusterId = null;

        if (all.Count < 2)
        {
            await db.SaveChangesAsync();
            return;
        }

        // Union-Find — algorithme transitif : si A-B et B-C sont liés, alors A-B-C forment un cluster
        var parent = all.ToDictionary(f => f.Id, f => f.Id);

        Guid Find(Guid id)
        {
            while (parent[id] != id)
                id = parent[id] = parent[parent[id]]; // path compression
            return id;
        }

        void Union(Guid a, Guid b)
        {
            var ra = Find(a); var rb = Find(b);
            if (ra != rb) parent[ra] = rb;
        }

        for (int i = 0; i < all.Count; i++)
            for (int j = i + 1; j < all.Count; j++)
                if (CountMatches(all[i], all[j]) >= threshold)
                    Union(all[i].Id, all[j].Id);

        // Regrouper par racine — ne conserver que les groupes de 2+ membres
        var groups = all.GroupBy(f => Find(f.Id)).Where(g => g.Count() > 1).ToList();

        foreach (var g in groups)
        {
            var members = g.ToList();
            // ID déterministe basé sur les HWIDs triés → les labels survivent aux re-scans
            var sortedHwids = string.Join("|", members.Select(m => m.HardwareId).OrderBy(h => h));
            var hashBytes = MD5.HashData(Encoding.UTF8.GetBytes(sortedHwids));
            var clusterId = new Guid(hashBytes);
            foreach (var m in members)
                m.ClusterId = clusterId;
        }

        await db.SaveChangesAsync();
        _logger.LogInformation("Clustering completed: {Total} fingerprints, {Clustered} in clusters, {GenericHashes} generic hashes filtered",
            all.Count, all.Count(f => f.ClusterId != null), _genericHashes.Count);
    }

    /// <summary>
    /// Compte les composants significativement identiques entre deux fingerprints.
    /// Les hashes correspondant à des valeurs WMI génériques sont ignorés.
    /// </summary>
    private static int CountMatches(HardwareFingerprint a, HardwareFingerprint b)
    {
        int count = 0;
        if (IsSignificantMatch(a.CpuHash, b.CpuHash)) count++;
        if (IsSignificantMatch(a.MotherboardHash, b.MotherboardHash)) count++;
        if (IsSignificantMatch(a.BiosHash, b.BiosHash)) count++;
        if (IsSignificantMatch(a.DiskHash, b.DiskHash)) count++;
        if (IsSignificantMatch(a.HostHash, b.HostHash)) count++;
        return count;
    }

    private static bool IsSignificantMatch(string? a, string? b)
    {
        if (string.IsNullOrEmpty(a) || string.IsNullOrEmpty(b)) return false;
        if (a != b) return false;
        return !_genericHashes.Contains(a);
    }

    private async Task<int> GetPositiveSettingAsync(string key, int defaultValue)
    {
        var raw = await _settings.GetSettingAsync(
            key, defaultValue.ToString(System.Globalization.CultureInfo.InvariantCulture));
        return int.TryParse(
            raw,
            System.Globalization.NumberStyles.Integer,
            System.Globalization.CultureInfo.InvariantCulture,
            out var value) && value > 0
                ? value
                : defaultValue;
    }

    public static bool IsGenericHash(string? hash)
        => !string.IsNullOrEmpty(hash) && _genericHashes.Contains(hash);

    public async Task<List<ClusterInfo>> GetClustersAsync()
    {
        using var db = await _dbFactory.CreateDbContextAsync();
        var fingerprints = await db.HardwareFingerprints.AsNoTracking()
            .Where(f => f.ClusterId != null)
            .OrderBy(f => f.ClusterId)
            .ToListAsync();

        var hwids = fingerprints.Select(f => f.HardwareId).ToList();

        // Cross-reference avec les sièges de licence pour les noms clients
        var seats = await db.LicenseSeats.AsNoTracking()
            .Include(s => s.License).ThenInclude(l => l!.Type)
            .Where(s => hwids.Contains(s.HardwareId) && s.IsActive)
            .ToListAsync();
        var seatsByHwid = seats.GroupBy(s => s.HardwareId)
            .ToDictionary(g => g.Key, g => g.ToList());

        var clusters = fingerprints
            .GroupBy(f => f.ClusterId!.Value)
            .Select(g =>
            {
                var members = g.ToList();
                var breakdown = GetBreakdown(members);
                return new ClusterInfo
                {
                    ClusterId = g.Key,
                    Breakdown = breakdown,
                    CommonComponents = breakdown.SharedCount,
                    Members = members.Select(f =>
                    {
                        var member = new ClusterMember
                        {
                            HardwareId = f.HardwareId,
                            FirstSeenAt = f.FirstSeenAt,
                            LastSeenAt = f.LastSeenAt,
                            CpuHash = f.CpuHash,
                            MotherboardHash = f.MotherboardHash,
                            BiosHash = f.BiosHash,
                            DiskHash = f.DiskHash,
                            HostHash = f.HostHash,
                        };
                        if (seatsByHwid.TryGetValue(f.HardwareId, out var memberSeats))
                        {
                            member.Licenses = memberSeats.Select(s => new ClusterMemberLicense
                            {
                                LicenseId = s.License?.Id ?? Guid.Empty,
                                CustomerName = s.License?.CustomerName ?? "",
                                CustomerEmail = s.License?.CustomerEmail ?? "",
                                TypeName = s.License?.Type?.Name ?? "",
                                IsActive = s.License?.IsActive ?? false
                            }).ToList();
                        }
                        return member;
                    }).ToList()
                };
            })
            .OrderByDescending(c => c.CommonComponents)
            .ThenByDescending(c => c.Members.Count)
            .ToList();

        // Charger les labels depuis les settings
        foreach (var c in clusters)
            c.Label = await _settings.GetSettingAsync($"ClusterLabel:{c.ClusterId}");

        return clusters;
    }

    /// <summary>
    /// Calcule quels composants sont réellement partagés par TOUS les membres du cluster,
    /// en excluant les valeurs WMI génériques.
    /// </summary>
    private static ComponentBreakdown GetBreakdown(List<HardwareFingerprint> members)
    {
        if (members.Count < 2) return new ComponentBreakdown();

        string? SharedHash(IEnumerable<string?> values)
        {
            var distinct = values.Where(v => !string.IsNullOrEmpty(v) && !_genericHashes.Contains(v)).Distinct().ToList();
            return distinct.Count == 1 ? distinct[0] : null;
        }

        var cpu = SharedHash(members.Select(m => m.CpuHash));
        var mb = SharedHash(members.Select(m => m.MotherboardHash));
        var bios = SharedHash(members.Select(m => m.BiosHash));
        var disk = SharedHash(members.Select(m => m.DiskHash));
        var host = SharedHash(members.Select(m => m.HostHash));

        return new ComponentBreakdown
        {
            CpuShared = cpu != null,
            MbShared = mb != null,
            BiosShared = bios != null,
            DiskShared = disk != null,
            HostShared = host != null,
            CpuHash = cpu,
            MbHash = mb,
            BiosHash = bios,
            DiskHash = disk,
            HostHash = host,
        };
    }

    public async Task<ClusterInfo?> GetClusterForHardwareIdAsync(string hardwareId)
    {
        using var db = await _dbFactory.CreateDbContextAsync();
        var fp = await db.HardwareFingerprints.AsNoTracking()
            .FirstOrDefaultAsync(f => f.HardwareId == hardwareId);
        if (fp?.ClusterId == null) return null;

        var clusters = await GetClustersAsync();
        return clusters.FirstOrDefault(c => c.ClusterId == fp.ClusterId);
    }

    public async Task<ClusterInfo?> GetClusterForHardwareIdsAsync(IEnumerable<string> hardwareIds)
    {
        using var db = await _dbFactory.CreateDbContextAsync();
        var fp = await db.HardwareFingerprints.AsNoTracking()
            .FirstOrDefaultAsync(f => hardwareIds.Contains(f.HardwareId) && f.ClusterId != null);
        if (fp?.ClusterId == null) return null;

        var clusters = await GetClustersAsync();
        return clusters.FirstOrDefault(c => c.ClusterId == fp.ClusterId);
    }

    public async Task SetClusterLabelAsync(Guid clusterId, string? label)
    {
        var key = $"ClusterLabel:{clusterId}";
        if (string.IsNullOrWhiteSpace(label))
            await _settings.SetSettingAsync(key, "");
        else
            await _settings.SetSettingAsync(key, label.Trim());
    }

    public async Task<List<HardwareFingerprint>> GetFingerprintsAsync(int page = 1, int pageSize = 50)
    {
        using var db = await _dbFactory.CreateDbContextAsync();
        return await db.HardwareFingerprints.AsNoTracking()
            .OrderByDescending(f => f.LastSeenAt)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .ToListAsync();
    }

    public async Task<string?> GetListTypeAsync(string hardwareId)
    {
        using var db = await _dbFactory.CreateDbContextAsync();
        return await db.HardwareFingerprints.AsNoTracking()
            .Where(f => f.HardwareId == hardwareId)
            .Select(f => f.ListType)
            .FirstOrDefaultAsync();
    }

    public async Task UpdateNoteAndListAsync(Guid id, string? note, string? listType)
    {
        using var db = await _dbFactory.CreateDbContextAsync();
        var fp = await db.HardwareFingerprints.FindAsync(id);
        if (fp == null) return;
        fp.Note = string.IsNullOrWhiteSpace(note) ? null : note.Trim();
        fp.ListType = listType;
        await db.SaveChangesAsync();
    }

    public async Task<List<EnrichedFingerprint>> GetEnrichedFingerprintsAsync(string? search = null)
    {
        using var db = await _dbFactory.CreateDbContextAsync();

        var query = db.HardwareFingerprints.AsNoTracking().AsQueryable();
        if (!string.IsNullOrWhiteSpace(search))
        {
            var s = search.Trim().ToLower();
            query = query.Where(f => f.HardwareId.ToLower().Contains(s)
                || (f.Note != null && f.Note.ToLower().Contains(s)));
        }

        var fingerprints = await query.OrderByDescending(f => f.LastSeenAt).Take(300).ToListAsync();
        var hwids = fingerprints.Select(f => f.HardwareId).ToList();

        var seats = await db.LicenseSeats.AsNoTracking()
            .Include(s => s.License).ThenInclude(l => l!.Type)
            .Include(s => s.License).ThenInclude(l => l!.Product)
            .Where(s => hwids.Contains(s.HardwareId) && s.IsActive)
            .ToListAsync();

        var seatsByHwid = seats.GroupBy(s => s.HardwareId)
            .ToDictionary(g => g.Key, g => g.ToList());

        var bannedHwids = (await db.BannedHardwareIds.AsNoTracking()
            .Where(b => hwids.Contains(b.HardwareId) && b.IsActive)
            .Select(b => b.HardwareId)
            .ToListAsync()).ToHashSet();

        return fingerprints.Select(fp =>
        {
            var enriched = new EnrichedFingerprint
            {
                Fingerprint = fp,
                IsBanned = bannedHwids.Contains(fp.HardwareId)
            };

            if (seatsByHwid.TryGetValue(fp.HardwareId, out var fpSeats))
            {
                enriched.Licenses = fpSeats.Select(s => new LicenseInfo
                {
                    LicenseId = s.License?.Id ?? Guid.Empty,
                    LicenseKey = s.License?.LicenseKey ?? "?",
                    CustomerName = s.License?.CustomerName ?? "",
                    CustomerEmail = s.License?.CustomerEmail ?? "",
                    TypeName = s.License?.Type?.Name ?? "",
                    ProductName = s.License?.Product?.Name ?? "",
                    IsActive = s.License?.IsActive ?? false,
                    ExpirationDate = s.License?.ExpirationDate,
                    AppVersion = s.AppVersion,
                    MachineName = s.MachineName
                }).ToList();
            }

            return enriched;
        }).ToList();
    }

    public async Task<ComponentFingerprintImpact> GetComponentImpactAsync(
        string componentType,
        string componentHash,
        Guid? productId = null)
    {
        var normalizedType = NormalizeComponentType(componentType);
        if (!SecurityService.TryNormalizeComponentHash(componentHash, out var normalizedHash))
            throw new ArgumentException(
                "component_hash_invalid: componentHash must be exactly 64 ASCII hexadecimal characters.",
                nameof(componentHash));
        using var db = await _dbFactory.CreateDbContextAsync();

        var query = db.HardwareFingerprints.AsNoTracking();
        query = normalizedType switch
        {
            "CPU" => query.Where(f => f.CpuHash != null && f.CpuHash.ToLower() == normalizedHash),
            "MB" => query.Where(f => f.MotherboardHash != null && f.MotherboardHash.ToLower() == normalizedHash),
            "BIOS" => query.Where(f => f.BiosHash != null && f.BiosHash.ToLower() == normalizedHash),
            "DISK" => query.Where(f => f.DiskHash != null && f.DiskHash.ToLower() == normalizedHash),
            "HOST" => query.Where(f => f.HostHash != null && f.HostHash.ToLower() == normalizedHash),
            _ => query.Where(_ => false)
        };

        var matches = await query
            .Select(f => new { f.HardwareId, f.FirstSeenAt, f.LastSeenAt })
            .ToListAsync();

        if (productId.HasValue && matches.Count > 0)
        {
            var candidateHardwareIds = matches.Select(match => match.HardwareId).ToList();
            var productHardwareIds = (await db.TelemetryRecords.AsNoTracking()
                    .Where(record => record.ProductId == productId
                        && candidateHardwareIds.Contains(record.HardwareId))
                    .Select(record => record.HardwareId)
                    .ToListAsync())
                .Concat(await db.Licenses.AsNoTracking()
                    .Where(license => license.ProductId == productId
                        && license.HardwareId != null
                        && candidateHardwareIds.Contains(license.HardwareId))
                    .Select(license => license.HardwareId!)
                    .ToListAsync())
                .Concat(await db.LicenseSeats.AsNoTracking()
                    .Where(seat => seat.License != null
                        && seat.License.ProductId == productId
                        && candidateHardwareIds.Contains(seat.HardwareId))
                    .Select(seat => seat.HardwareId)
                    .ToListAsync())
                .ToHashSet(StringComparer.Ordinal);
            matches = matches.Where(match => productHardwareIds.Contains(match.HardwareId)).ToList();
        }

        var hardwareIds = matches.Select(f => f.HardwareId)
            .Distinct(StringComparer.Ordinal)
            .ToList();

        var directLicenses = await db.Licenses.AsNoTracking()
            .Where(license => (!productId.HasValue || license.ProductId == productId)
                && license.HardwareId != null
                && hardwareIds.Contains(license.HardwareId))
            .Select(license => new { license.Id, license.CustomerEmail })
            .ToListAsync();
        var seatLicenses = await db.LicenseSeats.AsNoTracking()
            .Where(seat => hardwareIds.Contains(seat.HardwareId)
                && (!productId.HasValue || (seat.License != null && seat.License.ProductId == productId)))
            .Select(seat => new { seat.LicenseId, CustomerEmail = seat.License != null ? seat.License.CustomerEmail : null })
            .ToListAsync();

        var licenseIds = directLicenses.Select(license => license.Id)
            .Concat(seatLicenses.Select(license => license.LicenseId))
            .Distinct()
            .ToList();
        var accountCount = directLicenses.Select(license => license.CustomerEmail)
            .Concat(seatLicenses.Select(license => license.CustomerEmail))
            .Where(email => !string.IsNullOrWhiteSpace(email))
            .Select(email => email!.Trim().ToUpperInvariant())
            .Distinct(StringComparer.Ordinal)
            .Count();

        var clientIps = await db.TelemetryRecords.AsNoTracking()
            .Where(record => hardwareIds.Contains(record.HardwareId)
                && (!productId.HasValue || record.ProductId == productId)
                && record.ClientIp != null)
            .Select(record => record.ClientIp!)
            .Distinct()
            .ToListAsync();
        var genericThreshold = await GetPositiveSettingAsync("FingerprintGenericCardinalityThreshold", 3);
        var isHardwareComponent = normalizedType is "CPU" or "MB" or "BIOS" or "DISK" or "HOST";

        return new ComponentFingerprintImpact
        {
            ComponentType = normalizedType,
            ComponentHash = normalizedHash,
            DistinctHardwareIds = hardwareIds.Count,
            DistinctLicenses = licenseIds.Count,
            DistinctAccounts = accountCount,
            DistinctClientIps = clientIps.Count,
            FirstSeenAt = matches.Count == 0 ? null : matches.Min(match => match.FirstSeenAt),
            LastSeenAt = matches.Count == 0 ? null : matches.Max(match => match.LastSeenAt),
            GenericCardinalityThreshold = genericThreshold,
            ImpactAvailable = isHardwareComponent,
            ImpactUnavailableReason = isHardwareComponent
                ? null
                : "Binary fingerprint impact is release-scoped and is not represented by HardwareFingerprints.",
            IsGenericOrShared = isHardwareComponent
                && (IsGenericHash(normalizedHash) || hardwareIds.Count >= genericThreshold),
            IsEnforceable = SecurityService.IsEnforceableComponentType(normalizedType)
        };
    }

    private static string NormalizeComponentType(string componentType) =>
        componentType.Trim().ToUpperInvariant() switch
        {
            "FP_CPU" => "CPU",
            "FP_MB" => "MB",
            "FP_BIOS" => "BIOS",
            "FP_DISK" => "DISK",
            "FP_HOST" => "HOST",
            var normalized => normalized
        };

    public async Task<FingerprintStats> GetStatsAsync()
    {
        using var db = await _dbFactory.CreateDbContextAsync();
        var today = DateTime.UtcNow.Date;

        var total = await db.HardwareFingerprints.CountAsync();
        var clustered = await db.HardwareFingerprints.CountAsync(f => f.ClusterId != null);
        var newToday = await db.HardwareFingerprints.CountAsync(f => f.FirstSeenAt >= today);
        var whitelisted = await db.HardwareFingerprints.CountAsync(f => f.ListType == "white");
        var greylisted = await db.HardwareFingerprints.CountAsync(f => f.ListType == "grey");
        var clusterCount = await db.HardwareFingerprints
            .Where(f => f.ClusterId != null)
            .Select(f => f.ClusterId).Distinct().CountAsync();

        return new FingerprintStats
        {
            Total = total,
            Clustered = clustered,
            ClusterCount = clusterCount,
            NewToday = newToday,
            Whitelisted = whitelisted,
            Greylisted = greylisted
        };
    }
}

// ─────────────────────────────────────────────────────────────
// DTOs
// ─────────────────────────────────────────────────────────────

public class ComponentBreakdown
{
    public bool CpuShared { get; set; }
    public bool MbShared { get; set; }
    public bool BiosShared { get; set; }
    public bool DiskShared { get; set; }
    public bool HostShared { get; set; }
    public string? CpuHash { get; set; }
    public string? MbHash { get; set; }
    public string? BiosHash { get; set; }
    public string? DiskHash { get; set; }
    public string? HostHash { get; set; }
    public int SharedCount => (CpuShared ? 1 : 0) + (MbShared ? 1 : 0) + (BiosShared ? 1 : 0) + (DiskShared ? 1 : 0) + (HostShared ? 1 : 0);
}

public class EnrichedFingerprint
{
    public HardwareFingerprint Fingerprint { get; set; } = null!;
    public bool IsBanned { get; set; }
    public List<LicenseInfo> Licenses { get; set; } = new();
}

public class LicenseInfo
{
    public Guid LicenseId { get; set; }
    public string LicenseKey { get; set; } = "";
    public string CustomerName { get; set; } = "";
    public string CustomerEmail { get; set; } = "";
    public string TypeName { get; set; } = "";
    public string ProductName { get; set; } = "";
    public bool IsActive { get; set; }
    public DateTime? ExpirationDate { get; set; }
    public string? AppVersion { get; set; }
    public string? MachineName { get; set; }
}

public class FingerprintStats
{
    public int Total { get; set; }
    public int Clustered { get; set; }
    public int ClusterCount { get; set; }
    public int NewToday { get; set; }
    public int Whitelisted { get; set; }
    public int Greylisted { get; set; }
}

public sealed class ComponentFingerprintImpact
{
    public string ComponentType { get; set; } = string.Empty;
    public string ComponentHash { get; set; } = string.Empty;
    public int DistinctHardwareIds { get; set; }
    public int DistinctLicenses { get; set; }
    public int DistinctAccounts { get; set; }
    public int DistinctClientIps { get; set; }
    public DateTime? FirstSeenAt { get; set; }
    public DateTime? LastSeenAt { get; set; }
    public int GenericCardinalityThreshold { get; set; }
    public bool ImpactAvailable { get; set; }
    public string? ImpactUnavailableReason { get; set; }
    public bool IsGenericOrShared { get; set; }
    public bool IsEnforceable { get; set; }
}

public class RelatedHwid
{
    public string HardwareId { get; set; } = string.Empty;
    public int MatchCount { get; set; }
    public Guid? ClusterId { get; set; }
    public DateTime LastSeenAt { get; set; }
}

public class ClusterInfo
{
    public Guid ClusterId { get; set; }
    public List<ClusterMember> Members { get; set; } = new();
    public int CommonComponents { get; set; }
    public ComponentBreakdown Breakdown { get; set; } = new();
    public string? Label { get; set; }
}

public class ClusterMember
{
    public string HardwareId { get; set; } = string.Empty;
    public DateTime FirstSeenAt { get; set; }
    public DateTime LastSeenAt { get; set; }
    public List<ClusterMemberLicense> Licenses { get; set; } = new();
    public string? CpuHash { get; set; }
    public string? MotherboardHash { get; set; }
    public string? BiosHash { get; set; }
    public string? DiskHash { get; set; }
    public string? HostHash { get; set; }
}

public class ClusterMemberLicense
{
    public Guid LicenseId { get; set; }
    public string CustomerName { get; set; } = "";
    public string CustomerEmail { get; set; } = "";
    public string TypeName { get; set; } = "";
    public bool IsActive { get; set; }
}
