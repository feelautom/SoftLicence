using Microsoft.EntityFrameworkCore;
using SoftLicence.Server.Data;
using System.Collections.Concurrent;
using System.Security.Cryptography;
using Npgsql;

namespace SoftLicence.Server.Services;

public class SecurityService
{
    private readonly IDbContextFactory<LicenseDbContext> _dbFactory;
    private readonly ILogger<SecurityService> _logger;
    private readonly NotificationService _notifier;
    private readonly IConfiguration _config;
    private static readonly ConcurrentDictionary<string, (int Score, DateTime LastHit)> _threatScores = new();
    private static readonly ConcurrentDictionary<string, DateTime> _bannedCache = new();
    private static readonly ConcurrentDictionary<string, DateTime> _zombieNotifyCache = new();
    private static readonly ConcurrentDictionary<string, DateTime> _bannedHwidCache = new();
    private static readonly TimeSpan HwidCacheTtl = TimeSpan.FromMinutes(5);

    public SecurityService(IDbContextFactory<LicenseDbContext> dbFactory, ILogger<SecurityService> logger, NotificationService notifier, IConfiguration config)
    {
        _dbFactory = dbFactory;
        _logger = logger;
        _notifier = notifier;
        _config = config;
    }

    /// <summary>Vérifie si l'IP est dans la whitelist admin (immunité totale contre le scoring).</summary>
    public bool IsWhitelisted(string ip)
    {
        if (ip == "127.0.0.1" || ip == "::1") return true;
        // Exempt all private networks (RFC 1918) from threat scoring
        if (System.Net.IPAddress.TryParse(ip, out var addr))
        {
            // Handle IPv4-mapped IPv6 addresses (e.g. ::ffff:10.0.1.50 → 10.0.1.50)
            if (addr.IsIPv4MappedToIPv6)
                addr = addr.MapToIPv4();

            var bytes = addr.GetAddressBytes();
            if (bytes.Length == 4 && (
                bytes[0] == 10 ||                                          // 10.0.0.0/8
                (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) ||   // 172.16.0.0/12
                (bytes[0] == 192 && bytes[1] == 168) ||                    // 192.168.0.0/16
                (bytes[0] == 127)))                                        // 127.0.0.0/8 (loopback)
                return true;
        }
        var allowedIpsStr = _config["AdminSettings:AllowedIps"];
        if (string.IsNullOrEmpty(allowedIpsStr)) return false;
        var allowedIps = allowedIpsStr.Split(',').Select(i => i.Trim()).ToList();
        return allowedIps.Contains(ip);
    }

    public async Task<bool> IsBannedAsync(string ip)
    {
        if (IsWhitelisted(ip)) return false;

        if (_bannedCache.TryGetValue(ip, out var expiry))
        {
            if (expiry > DateTime.UtcNow) return true;
            _bannedCache.TryRemove(ip, out _);
        }

        using var db = await _dbFactory.CreateDbContextAsync();
        var ban = await db.BannedIps.FirstOrDefaultAsync(b => b.IpAddress == ip && b.IsActive);

        if (ban != null)
        {
            if (ban.ExpiresAt == null || ban.ExpiresAt > DateTime.UtcNow)
            {
                _bannedCache[ip] = ban.ExpiresAt ?? DateTime.MaxValue;
                return true;
            }

            ban.IsActive = false;
            await db.SaveChangesAsync();
        }

        return false;
    }

    public async Task<int> GetBanCountAsync(string ip)
    {
        using var db = await _dbFactory.CreateDbContextAsync();
        var ban = await db.BannedIps.AsNoTracking().FirstOrDefaultAsync(b => b.IpAddress == ip);
        return ban?.BanCount ?? 0;
    }

    public async Task ReportThreatAsync(string ip, int points, string reason)
    {
        if (ip == "127.0.0.1" || ip == "::1" || ip == "Unknown") return;

        // Immunité : les IPs whitelisted ne sont jamais scorées
        if (IsWhitelisted(ip)) return;

        var now = DateTime.UtcNow;

        // Restauration depuis la BDD si absent de la mémoire (ex : redémarrage serveur)
        if (!_threatScores.ContainsKey(ip))
        {
            using var dbRestore = await _dbFactory.CreateDbContextAsync();
            var dbScore = await dbRestore.IpThreatScores.FindAsync(ip);
            if (dbScore != null)
                _threatScores.TryAdd(ip, (dbScore.Score, dbScore.LastHit));
        }

        // Accumulation permanente — plus de décroissance 1h (score persisté)
        var entry = _threatScores.AddOrUpdate(ip,
            (points, now),
            (key, old) => (old.Score + points, now));

        // Persistance en BDD (fire-and-forget, best effort)
        _ = Task.Run(async () =>
        {
            try
            {
                using var db = await _dbFactory.CreateDbContextAsync();
                var existing = await db.IpThreatScores.FindAsync(ip);
                if (existing != null)
                {
                    existing.Score = entry.Score;
                    existing.LastHit = entry.LastHit;
                }
                else
                {
                    db.IpThreatScores.Add(new Data.IpThreatScore
                    {
                        IpAddress = ip,
                        Score = entry.Score,
                        LastHit = entry.LastHit
                    });
                }
                await db.SaveChangesAsync();
            }
            catch { /* Best effort */ }
        });

        if (entry.Score >= 200)
        {
            await BanIpAsync(ip, reason + $" (Score: {entry.Score})");
            _threatScores.TryRemove(ip, out _);
        }
    }

    /// <summary>Purge le cache mémoire de ban pour cette IP (à appeler après un unban en BDD).</summary>
    public void EvictBanCache(string ip)
    {
        _bannedCache.TryRemove(ip, out _);
        _threatScores.TryRemove(ip, out _);
    }

    public int GetThreatScore(string ip)
    {
        if (_threatScores.TryGetValue(ip, out var entry))
            return entry.Score;
        return 0;
    }

    public async Task BanIpAsync(string ip, string reason)
    {
        if (IsWhitelisted(ip)) return;

        using var db = await _dbFactory.CreateDbContextAsync();
        var existing = await db.BannedIps.FirstOrDefaultAsync(b => b.IpAddress == ip);

        if (existing != null)
        {
            if (existing.IsActive) return; // Already actively banned

            ReactivateExistingIpBan(existing, reason);

            await db.SaveChangesAsync();
            _bannedCache[ip] = existing.ExpiresAt ?? DateTime.MaxValue;

            _logger.LogCritical("IP BANNIE (Récidive x{Count}) : {IP} pour {Reason} — Durée escaladée", existing.BanCount, ip, reason);

            _notifier.Notify(NotificationService.Triggers.SecurityIpBanned,
                $"🚫 IP BANNIE (x{existing.BanCount})",
                $"IP: {ip}\nRaison: {reason}\nRécidive #{existing.BanCount}");
        }
        else
        {
            var ban = new BannedIp
            {
                IpAddress = ip,
                Reason = reason,
                BannedAt = DateTime.UtcNow,
                ExpiresAt = DateTime.UtcNow.AddDays(1)
            };

            db.BannedIps.Add(ban);
            try
            {
                await db.SaveChangesAsync();
            }
            catch (DbUpdateException ex) when (IsUniqueConstraintViolation(ex))
            {
                db.Entry(ban).State = EntityState.Detached;
                existing = await db.BannedIps.FirstOrDefaultAsync(b => b.IpAddress == ip);
                if (existing == null)
                    throw;

                if (existing.IsActive)
                {
                    if (existing.ExpiresAt.HasValue)
                        _bannedCache[ip] = existing.ExpiresAt.Value;

                    _logger.LogInformation("IP ban race ignored: {IP} was already active while inserting duplicate ban.", ip);
                    return;
                }

                ReactivateExistingIpBan(existing, reason);
                await db.SaveChangesAsync();
                _bannedCache[ip] = existing.ExpiresAt ?? DateTime.MaxValue;

                _logger.LogCritical("IP BANNIE (Récidive x{Count}) : {IP} pour {Reason} — Durée escaladée après conflit concurrent", existing.BanCount, ip, reason);

                _notifier.Notify(NotificationService.Triggers.SecurityIpBanned,
                    $"🚫 IP BANNIE (x{existing.BanCount})",
                    $"IP: {ip}\nRaison: {reason}\nRécidive #{existing.BanCount}");

                _ = ClearThreatScoreAsync(ip);
                return;
            }

            _bannedCache[ip] = ban.ExpiresAt.Value;

            _logger.LogCritical("IP BANNIE AUTOMATIQUEMENT : {IP} pour {Reason}", ip, reason);

            _notifier.Notify(NotificationService.Triggers.SecurityIpBanned,
                "🚫 IP BANNIE",
                $"IP: {ip}\nRaison: {reason}\nScore dépassé.");
        }

        // Remettre le score à zéro en BDD après le ban — l'IP repart de 0 après sa peine
        _ = ClearThreatScoreAsync(ip);
    }

    private static void ReactivateExistingIpBan(BannedIp ban, string reason)
    {
        var now = DateTime.UtcNow;
        ban.BanCount++;
        ban.IsActive = true;
        ban.Reason = reason;
        ban.BannedAt = now;
        ban.ExpiresAt = ban.BanCount switch
        {
            1 => now.AddDays(1),
            2 => now.AddDays(7),
            _ => now.AddDays(30)
        };
    }

    private static bool IsUniqueConstraintViolation(DbUpdateException ex)
    {
        return ex.InnerException is PostgresException { SqlState: PostgresErrorCodes.UniqueViolation };
    }

    private Task ClearThreatScoreAsync(string ip)
    {
        return Task.Run(async () =>
        {
            try
            {
                using var scoreDb = await _dbFactory.CreateDbContextAsync();
                var scoreEntry = await scoreDb.IpThreatScores.FindAsync(ip);
                if (scoreEntry != null)
                {
                    scoreDb.IpThreatScores.Remove(scoreEntry);
                    await scoreDb.SaveChangesAsync();
                }
            }
            catch { /* Best effort */ }
        });
    }

    // --- HARDWARE ID BLACKLIST ---

    public async Task<bool> IsHardwareIdBannedAsync(string hardwareId, Guid? productId = null)
    {
        if (string.IsNullOrEmpty(hardwareId)) return false;

        var cacheKey = productId.HasValue ? $"{hardwareId}:{productId}" : hardwareId;

        if (_bannedHwidCache.TryGetValue(cacheKey, out var cachedAt))
        {
            if (DateTime.UtcNow - cachedAt < HwidCacheTtl) return true;
            _bannedHwidCache.TryRemove(cacheKey, out _);
        }

        using var db = await _dbFactory.CreateDbContextAsync();
        var ban = await db.BannedHardwareIds.FirstOrDefaultAsync(b =>
            b.HardwareId == hardwareId && b.IsActive &&
            (b.ProductId == null || !productId.HasValue || b.ProductId == productId));

        if (ban != null)
        {
            if (ban.ExpiresAt == null || ban.ExpiresAt > DateTime.UtcNow)
            {
                _bannedHwidCache[cacheKey] = DateTime.UtcNow;
                return true;
            }

            ban.IsActive = false;
            await db.SaveChangesAsync();
        }

        return false;
    }

    public async Task<Data.BannedHardwareId?> GetActiveHardwareBanAsync(string hardwareId, Guid? productId = null)
    {
        if (string.IsNullOrEmpty(hardwareId)) return null;

        using var db = await _dbFactory.CreateDbContextAsync();
        var ban = await db.BannedHardwareIds
            .Where(b => b.HardwareId == hardwareId && b.IsActive
                && (b.ProductId == null || !productId.HasValue || b.ProductId == productId))
            .OrderByDescending(b => b.BannedAt)
            .FirstOrDefaultAsync();

        if (ban == null)
            return null;

        if (ban.ExpiresAt == null || ban.ExpiresAt > DateTime.UtcNow)
            return ban;

        ban.IsActive = false;
        await db.SaveChangesAsync();

        var cacheKey = productId.HasValue ? $"{hardwareId}:{productId}" : hardwareId;
        _bannedHwidCache.TryRemove(cacheKey, out _);
        return null;
    }

    public async Task BanHardwareIdAsync(string hardwareId, string reason, Guid? productId = null, DateTime? expiresAt = null, Guid? piracySuspectId = null, string? banCategory = null, bool silent = false)
    {
        if (string.IsNullOrEmpty(hardwareId)) return;

        using var db = await _dbFactory.CreateDbContextAsync();

        // Check if HWID is whitelisted/greylisted (immune to auto-ban)
        bool isProtected = false;
        if (reason.StartsWith("Auto-ban:"))
        {
            var listType = await db.HardwareFingerprints.AsNoTracking()
                .Where(f => f.HardwareId == hardwareId)
                .Select(f => f.ListType)
                .FirstOrDefaultAsync();
            if (listType == "white" || listType == "grey")
                isProtected = true;
        }

        var existing = await db.BannedHardwareIds.FirstOrDefaultAsync(b =>
            b.HardwareId == hardwareId &&
            (b.ProductId == null || b.ProductId == productId));

        if (existing != null)
        {
            // Record the entry but set inactive if protected (keep history)
            existing.IsActive = !isProtected;
            existing.Reason = isProtected ? $"[PROTECTED:{reason}]" : reason;
            existing.BannedAt = DateTime.UtcNow;
            existing.ExpiresAt = expiresAt;
            if (banCategory != null) existing.BanCategory = banCategory;
            if (piracySuspectId.HasValue) existing.PiracySuspectId = piracySuspectId;
        }
        else
        {
            db.BannedHardwareIds.Add(new Data.BannedHardwareId
            {
                HardwareId = hardwareId,
                ProductId = productId,
                // Save entry but inactive if protected (keeps history visible)
                IsActive = !isProtected,
                Reason = isProtected ? $"[PROTECTED:{reason}]" : reason,
                BanCategory = banCategory,
                ExpiresAt = expiresAt,
                PiracySuspectId = piracySuspectId
            });
        }

        await db.SaveChangesAsync();

        if (isProtected)
        {
            _logger.LogInformation("HWID {HardwareId} protected (whitelist/greylist) - entry saved inactive: {Reason}", hardwareId, reason);
            return;
        }

        var cacheKey = productId.HasValue ? $"{hardwareId}:{productId}" : hardwareId;
        _bannedHwidCache[cacheKey] = DateTime.UtcNow;

        _logger.LogCritical("HARDWARE ID BANNI{Silent} : {HardwareId} pour {Reason}",
            silent ? " [SILENT]" : "", hardwareId, reason);
        if (!silent)
            _notifier.Notify(NotificationService.Triggers.SecurityIpBanned,
                "HARDWARE ID BANNI",
                $"HWID: {hardwareId}\nRaison: {reason}");
    }

    public async Task UnbanHardwareIdAsync(Guid banId)
    {
        using var db = await _dbFactory.CreateDbContextAsync();
        var ban = await db.BannedHardwareIds.FindAsync(banId);
        if (ban == null) return;

        ban.IsActive = false;
        await db.SaveChangesAsync();

        // Evict from cache
        var cacheKey = ban.ProductId.HasValue ? $"{ban.HardwareId}:{ban.ProductId}" : ban.HardwareId;
        _bannedHwidCache.TryRemove(cacheKey, out _);

        _logger.LogInformation("HARDWARE ID DEBANNI : {HardwareId}", ban.HardwareId);
    }

    /// <summary>
    /// Auto-unban a HWID that was auto-banned for version violation, if they updated.
    /// Only unbans entries whose Reason starts with "Auto-ban:".
    /// Also unbans associated components.
    /// </summary>
    public async Task<bool> AutoUnbanByHwidAsync(string hardwareId, Guid productId)
    {
        if (string.IsNullOrEmpty(hardwareId)) return false;

        using var db = await _dbFactory.CreateDbContextAsync();
        var bans = await db.BannedHardwareIds
            .Where(b => b.HardwareId == hardwareId && b.IsActive && b.ProductId == productId
                && b.Reason.StartsWith("Auto-ban:"))
            .ToListAsync();

        if (bans.Count == 0) return false;

        foreach (var ban in bans)
        {
            // Never auto-unban permanent categories
            if (Data.BannedHardwareId.Categories.Permanent.Contains(ban.BanCategory))
                continue;
            ban.IsActive = false;
        }

        // Also unban components linked to this auto-ban
        var componentBans = await db.BannedComponents
            .Where(b => b.IsActive && b.ProductId == productId
                && b.Reason.StartsWith("Auto-ban:") && b.Reason.Contains(hardwareId))
            .ToListAsync();
        foreach (var cb in componentBans)
        {
            cb.IsActive = false;
            var compCacheKey = $"comp:{cb.ComponentType}:{cb.ComponentHash}:{cb.ProductId}";
            _bannedComponentCache.TryRemove(compCacheKey, out _);
        }

        await db.SaveChangesAsync();

        // Evict HWID from cache
        var cacheKey = $"{hardwareId}:{productId}";
        _bannedHwidCache.TryRemove(cacheKey, out _);

        _logger.LogWarning("AUTO-UNBAN: {HardwareId} (updated to compliant version). {BanCount} bans + {CompCount} components lifted.",
            hardwareId, bans.Count, componentBans.Count);

        _notifier.Notify(NotificationService.Triggers.SecurityIpBanned,
            "AUTO-UNBAN VERSION",
            $"HWID: {hardwareId}\nMis à jour vers version conforme.\n{bans.Count} ban(s) + {componentBans.Count} composant(s) levés.");

        return true;
    }

    /// <summary>
    /// At paid license activation, auto-unban if the ban category allows it.
    /// Returns (canProceed, permanentBan) — if permanentBan is true, activation must be refused.
    /// </summary>
    public async Task<(bool canProceed, bool permanentBan)> TryAutoUnbanForPaidLicenseAsync(string hardwareId, Guid productId)
    {
        if (string.IsNullOrEmpty(hardwareId)) return (true, false);

        using var db = await _dbFactory.CreateDbContextAsync();
        var activeBans = await db.BannedHardwareIds
            .Where(b => b.HardwareId == hardwareId && b.IsActive
                && (b.ProductId == null || b.ProductId == productId))
            .ToListAsync();

        if (activeBans.Count == 0) return (true, false);

        // Check if any ban is permanent (debugger, piracy)
        var hasPermanent = activeBans.Any(b =>
            Data.BannedHardwareId.Categories.Permanent.Contains(b.BanCategory));
        if (hasPermanent)
        {
            _logger.LogWarning("Paid activation blocked for {HardwareId}: permanent ban ({Categories})",
                hardwareId, string.Join(", ", activeBans.Where(b => Data.BannedHardwareId.Categories.Permanent.Contains(b.BanCategory)).Select(b => b.BanCategory)));
            return (false, true);
        }

        // Check if any ban is manual (admin decides)
        var hasManual = activeBans.Any(b => b.BanCategory == Data.BannedHardwareId.Categories.Manual || b.BanCategory == null);
        if (hasManual)
        {
            _logger.LogInformation("Paid activation blocked for {HardwareId}: manual ban requires admin review", hardwareId);
            return (false, false);
        }

        // All remaining bans are auto-unbannable (quota_abuse, outdated_version)
        foreach (var ban in activeBans)
        {
            ban.IsActive = false;
        }
        await db.SaveChangesAsync();

        // Evict from cache
        var cacheKey = productId != Guid.Empty ? $"{hardwareId}:{productId}" : hardwareId;
        _bannedHwidCache.TryRemove(cacheKey, out _);
        _bannedHwidCache.TryRemove(hardwareId, out _);

        _logger.LogWarning("AUTO-UNBAN PAID LICENSE: {HardwareId} - {Count} ban(s) lifted ({Categories})",
            hardwareId, activeBans.Count, string.Join(", ", activeBans.Select(b => b.BanCategory)));

        var categories = activeBans
            .Select(b => b.BanCategory ?? Data.BannedHardwareId.Categories.Manual)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
        var isOutdatedOnly = categories.Count == 1
            && categories[0] == Data.BannedHardwareId.Categories.OutdatedVersion;
        var title = isOutdatedOnly
            ? "AUTO-UNBAN VERSION OBSOLETE"
            : "AUTO-UNBAN LICENCE PAYANTE";
        var reason = isOutdatedOnly
            ? "Déblocage d'un ban version obsolète sur licence payante valide."
            : "Activation licence payante valide.";

        _notifier.Notify(NotificationService.Triggers.SecurityIpBanned,
            title,
            $"HWID: {hardwareId}\n{reason}\n{activeBans.Count} ban(s) levé(s) (catégories: {string.Join(", ", categories)}).");

        return (true, false);
    }

    public async Task<List<Data.BannedHardwareId>> GetBannedHardwareIdsAsync()
    {
        using var db = await _dbFactory.CreateDbContextAsync();
        return await db.BannedHardwareIds
            .Include(b => b.Product)
            .OrderByDescending(b => b.BannedAt)
            .ToListAsync();
    }

    public async Task CheckForZombieAsync(string hardwareId, string currentIp)
    {
        if (string.IsNullOrEmpty(hardwareId) || hardwareId == "Unknown") return;
        if (IsWhitelisted(currentIp)) return;

        using var db = await _dbFactory.CreateDbContextAsync();

        // Skip whitelisted/greylisted HWIDs
        var listType = await db.HardwareFingerprints.AsNoTracking()
            .Where(f => f.HardwareId == hardwareId)
            .Select(f => f.ListType)
            .FirstOrDefaultAsync();
        if (listType == "white" || listType == "grey") return;

        // 1. Analyse : Combien d'IP différentes pour ce HardwareID depuis 24h ?
        var recentIps = await db.AccessLogs
            .Where(l => l.HardwareId == hardwareId && l.Timestamp > DateTime.UtcNow.AddHours(-24))
            .Select(l => l.ClientIp)
            .Distinct()
            .ToListAsync();

        // Si l'IP actuelle n'est pas encore en base (car loggée après), on l'ajoute virtuellement pour le compte
        if (!recentIps.Contains(currentIp) && currentIp != "Unknown" && currentIp != "127.0.0.1")
        {
            recentIps.Add(currentIp);
        }

        // EXEMPTION : Les licences freemium/trial (1 siège) ne sont pas concernées par le zombie
        // Le zombie ne protège que les licences payantes multi-sièges (partage de HWID patché)
        var activeLicense = await db.Licenses
            .Include(l => l.Type)
            .FirstOrDefaultAsync(l => l.IsActive && (l.HardwareId == hardwareId || l.Seats.Any(s => s.HardwareId == hardwareId)));

        if (activeLicense?.Type != null && activeLicense.Type.DefaultMaxSeats <= 1)
        {
            return; // Freemium/Trial : pas de zombie detection
        }

        // 2. Comptage intelligent : on compte les sous-réseaux /24 distincts au lieu des IPs brutes
        // Un VPN rotatif génère beaucoup d'IPs mais dans très peu de sous-réseaux
        var distinctSubnets = recentIps
            .Where(ip => System.Net.IPAddress.TryParse(ip, out _))
            .Select(ip =>
            {
                var parts = ip.Split('.');
                return parts.Length == 4 ? $"{parts[0]}.{parts[1]}.{parts[2]}" : ip;
            })
            .Distinct()
            .Count();

        // Anti-flood : On ne notifie que si aucune alerte n'a été envoyée pour ce HWID dans les 6 dernières heures
        var shouldNotify = true;
        if (_zombieNotifyCache.TryGetValue(hardwareId, out var lastNotify))
        {
            if (DateTime.UtcNow - lastNotify < TimeSpan.FromHours(6))
            {
                shouldNotify = false;
            }
        }

        // PALIER 1 — ALERTE : Plus de 5 sous-réseaux /24 distincts en 24h → notification de surveillance
        // (beaucoup d'IPs dans peu de sous-réseaux = VPN rotatif = faux positif)
        if (distinctSubnets > 5 && distinctSubnets <= 8)
        {
            _logger.LogWarning("ZOMBIE WARNING : HardwareID {Hwid} seen on {Count} IPs across {Subnets} subnets (surveillance)", hardwareId, recentIps.Count, distinctSubnets);

            if (shouldNotify)
            {
                _zombieNotifyCache[hardwareId] = DateTime.UtcNow;
                _notifier.Notify(NotificationService.Triggers.SecurityZombieDetected,
                    "⚠️ ZOMBIE WARNING (Surveillance)",
                    $"HardwareID: {hardwareId}\nIPs: {recentIps.Count} ({distinctSubnets} sous-réseaux)\nSeuil d'alerte atteint — pas de révocation. Surveillance en cours.");
            }
        }

        // PALIER 2 — ALERTE CRITIQUE : Plus de 8 sous-réseaux distincts en 24h → alerte sans révocation auto
        if (distinctSubnets > 8)
        {
            _logger.LogCritical("ZOMBIE DETECTED : HardwareID {Hwid} seen on {Count} IPs across {Subnets} subnets!", hardwareId, recentIps.Count, distinctSubnets);

            if (shouldNotify)
            {
                _zombieNotifyCache[hardwareId] = DateTime.UtcNow;
                var licInfo = activeLicense != null ? $"\nLicence: {activeLicense.LicenseKey}" : "\nAucune licence active";
                _notifier.Notify(NotificationService.Triggers.SecurityZombieDetected,
                    "🧟 ZOMBIE DETECTED (Action manuelle requise)",
                    $"HardwareID: {hardwareId}\nIPs: {recentIps.Count} ({distinctSubnets} sous-réseaux){licInfo}");
            }
        }
    }

    // --- COMPONENT FINGERPRINT BLACKLIST ---

    private static readonly ConcurrentDictionary<string, DateTime> _bannedComponentCache = new();
    private static readonly TimeSpan ComponentCacheTtl = TimeSpan.FromMinutes(5);

    private static string NormalizeComponentType(string componentType)
    {
        return componentType.Trim().ToUpperInvariant() switch
        {
            "FP_CPU" => "CPU",
            "FP_MB" => "MB",
            "FP_BIOS" => "BIOS",
            "FP_DISK" => "DISK",
            "FP_HOST" => "HOST",
            "FP_EXE" => "FP_EXE",
            "FP_DLL" => "FP_DLL",
            "FP_CORE" => "FP_CORE",
            var normalized => normalized
        };
    }

    public async Task<(bool IsBanned, string ComponentType, string Reason)> IsComponentBannedAsync(Dictionary<string, string> fingerprints, Guid? productId = null)
    {
        if (fingerprints == null || fingerprints.Count == 0)
            return (false, "", "");

        var componentMap = new Dictionary<string, string>
        {
            ["FP_CPU"] = "CPU",
            ["FP_MB"] = "MB",
            ["FP_BIOS"] = "BIOS",
            ["FP_DISK"] = "DISK",
            ["FP_HOST"] = "HOST",
            ["FP_EXE"] = "FP_EXE",
            ["FP_DLL"] = "FP_DLL",
            ["FP_CORE"] = "FP_CORE"
        };

        // Check cache first
        foreach (var (key, type) in componentMap)
        {
            if (!fingerprints.TryGetValue(key, out var hash) || string.IsNullOrEmpty(hash)) continue;
            var cacheKey = $"comp:{type}:{hash}:{productId}";
            if (_bannedComponentCache.TryGetValue(cacheKey, out var cachedAt) && DateTime.UtcNow - cachedAt < ComponentCacheTtl)
                return (true, type, "Cached ban");
        }

        using var db = await _dbFactory.CreateDbContextAsync();

        foreach (var (key, type) in componentMap)
        {
            if (!fingerprints.TryGetValue(key, out var hash) || string.IsNullOrEmpty(hash)) continue;

            var ban = await db.BannedComponents.FirstOrDefaultAsync(b =>
                b.ComponentType == type && b.ComponentHash == hash && b.IsActive &&
                (b.ProductId == null || b.ProductId == productId));

            if (ban != null)
            {
                if (ban.ExpiresAt == null || ban.ExpiresAt > DateTime.UtcNow)
                {
                    var cacheKey = $"comp:{type}:{hash}:{productId}";
                    _bannedComponentCache[cacheKey] = DateTime.UtcNow;
                    return (true, type, ban.Reason);
                }

                ban.IsActive = false;
                await db.SaveChangesAsync();
            }
        }

        return (false, "", "");
    }

    public async Task BanComponentAsync(string componentType, string componentHash, string reason, Guid? productId = null, DateTime? expiresAt = null, bool silent = false)
    {
        if (string.IsNullOrEmpty(componentType) || string.IsNullOrEmpty(componentHash)) return;

        componentType = NormalizeComponentType(componentType);

        using var db = await _dbFactory.CreateDbContextAsync();

        var existing = await db.BannedComponents.FirstOrDefaultAsync(b =>
            b.ComponentType == componentType && b.ComponentHash == componentHash &&
            (b.ProductId == null || b.ProductId == productId));

        if (existing != null)
        {
            existing.IsActive = true;
            existing.Reason = reason;
            existing.BannedAt = DateTime.UtcNow;
            existing.ExpiresAt = expiresAt;
        }
        else
        {
            db.BannedComponents.Add(new BannedComponent
            {
                ComponentType = componentType,
                ComponentHash = componentHash,
                ProductId = productId,
                Reason = reason,
                ExpiresAt = expiresAt
            });
        }

        await db.SaveChangesAsync();

        var cacheKey = $"comp:{componentType}:{componentHash}:{productId}";
        _bannedComponentCache[cacheKey] = DateTime.UtcNow;

        _logger.LogCritical("COMPONENT BANNED{Silent}: {Type}={Hash} for {Reason}",
            silent ? " [SILENT]" : "", componentType, componentHash, reason);
        if (!silent)
            _notifier.Notify(NotificationService.Triggers.SecurityIpBanned,
                "COMPONENT BANNED",
                $"Type: {componentType}\nHash: {componentHash}\nReason: {reason}");
    }

    public async Task UnbanComponentAsync(Guid banId)
    {
        using var db = await _dbFactory.CreateDbContextAsync();
        var ban = await db.BannedComponents.FindAsync(banId);
        if (ban == null) return;

        ban.IsActive = false;
        await db.SaveChangesAsync();

        var cacheKey = $"comp:{ban.ComponentType}:{ban.ComponentHash}:{ban.ProductId}";
        _bannedComponentCache.TryRemove(cacheKey, out _);

        _logger.LogInformation("COMPONENT UNBANNED: {Type}={Hash}", ban.ComponentType, ban.ComponentHash);
    }

    public async Task<List<BannedComponent>> GetBannedComponentsAsync()
    {
        using var db = await _dbFactory.CreateDbContextAsync();
        return await db.BannedComponents
            .Include(b => b.Product)
            .Where(b => b.IsActive)
            .OrderByDescending(b => b.BannedAt)
            .ToListAsync();
    }

    // --- GESTION DES MOTS DE PASSE ---

    public string HashPassword(string password)
    {
        return BCrypt.Net.BCrypt.HashPassword(password, 12);
    }

    public bool VerifyPassword(string password, string hash)
    {
        try { return BCrypt.Net.BCrypt.Verify(password, hash); }
        catch { return false; }
    }

    public string GenerateSecurePassword()
    {
        const string upper = "ABCDEFGHJKLMNPQRSTUVWXYZ"; // No I, O to avoid confusion
        const string lower = "abcdefghijkmnopqrstuvwxyz"; // No l
        const string digits = "23456789"; // No 0, 1
        const string all = upper + lower + digits;

        var chars = new char[15];

        // Ensure at least one of each for complexity
        chars[0] = upper[RandomNumberGenerator.GetInt32(upper.Length)];
        chars[1] = lower[RandomNumberGenerator.GetInt32(lower.Length)];
        chars[2] = digits[RandomNumberGenerator.GetInt32(digits.Length)];

        for (int i = 3; i < 15; i++)
        {
            chars[i] = all[RandomNumberGenerator.GetInt32(all.Length)];
        }

        // Shuffle (Fisher-Yates with crypto RNG)
        for (int i = chars.Length - 1; i > 0; i--)
        {
            int j = RandomNumberGenerator.GetInt32(i + 1);
            (chars[i], chars[j]) = (chars[j], chars[i]);
        }

        return new string(chars);
    }
}
