using Microsoft.EntityFrameworkCore;
using SoftLicence.Server.Data;
using System.Collections.Concurrent;
using System.Security.Cryptography;

namespace SoftLicence.Server.Services;

public class SecurityService
{
    private readonly IDbContextFactory<LicenseDbContext> _dbFactory;
    private readonly ILogger<SecurityService> _logger;
    private readonly NotificationService _notifier;
    private readonly IConfiguration _config;
    private static readonly ConcurrentDictionary<string, (int Score, DateTime LastHit)> _threatScores = new();
    private static readonly ConcurrentDictionary<string, DateTime> _bannedCache = new();

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
        var allowedIpsStr = _config["AdminSettings:AllowedIps"];
        if (string.IsNullOrEmpty(allowedIpsStr)) return false;
        var allowedIps = allowedIpsStr.Split(',').Select(i => i.Trim()).ToList();
        return allowedIps.Contains(ip);
    }

    public async Task<bool> IsBannedAsync(string ip)
    {
        if (ip == "127.0.0.1" || ip == "::1") return false;

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

    public int GetThreatScore(string ip)
    {
        if (_threatScores.TryGetValue(ip, out var entry))
            return entry.Score;
        return 0;
    }

    public async Task BanIpAsync(string ip, string reason)
    {
        using var db = await _dbFactory.CreateDbContextAsync();
        var existing = await db.BannedIps.FirstOrDefaultAsync(b => b.IpAddress == ip);

        if (existing != null)
        {
            if (existing.IsActive) return; // Already actively banned

            existing.BanCount++;
            existing.IsActive = true;
            existing.Reason = reason;
            existing.BannedAt = DateTime.UtcNow;
            existing.ExpiresAt = existing.BanCount switch
            {
                1 => DateTime.UtcNow.AddDays(1),
                2 => DateTime.UtcNow.AddDays(7),
                _ => DateTime.UtcNow.AddDays(30)
            };

            await db.SaveChangesAsync();
            _bannedCache[ip] = existing.ExpiresAt.Value;

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
            await db.SaveChangesAsync();
            _bannedCache[ip] = ban.ExpiresAt.Value;

            _logger.LogCritical("IP BANNIE AUTOMATIQUEMENT : {IP} pour {Reason}", ip, reason);

            _notifier.Notify(NotificationService.Triggers.SecurityIpBanned,
                "🚫 IP BANNIE",
                $"IP: {ip}\nRaison: {reason}\nScore dépassé.");
        }

        // Remettre le score à zéro en BDD après le ban — l'IP repart de 0 après sa peine
        _ = Task.Run(async () =>
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

    public async Task CheckForZombieAsync(string hardwareId, string currentIp)
    {
        if (string.IsNullOrEmpty(hardwareId) || hardwareId == "Unknown") return;

        using var db = await _dbFactory.CreateDbContextAsync();

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

        // SEUIL ZOMBIE : Plus de 5 IPs différentes en 24h pour le même matériel
        if (recentIps.Count > 5)
        {
            _logger.LogCritical("ZOMBIE DETECTED : HardwareID {Hwid} seen on {Count} IPs !", hardwareId, recentIps.Count);

            // 2. RIPOSTE : Trouver la licence active liée à ce HardwareID
            var license = await db.Licenses.FirstOrDefaultAsync(l => l.HardwareId == hardwareId && l.IsActive);
            
            if (license != null)
            {
                license.IsActive = false;
                license.RevocationReason = "FRAUDE DETECTEE (ZOMBIE) : Partage de licence suspect (Seuil > 5 IPs/24h).";
                license.RevokedAt = DateTime.UtcNow;
                
                await db.SaveChangesAsync();

                _logger.LogCritical("LICENCE REVOQUEE : {Key} (Fraude Zombie)", license.LicenseKey);
                
                _notifier.Notify(NotificationService.Triggers.SecurityZombieDetected,
                    "🧟 ZOMBIE DETECTED",
                    $"HardwareID: {hardwareId}\nIPs: {recentIps.Count}\nLICENCE {license.LicenseKey} RÉVOQUÉE.");
            }
            else
            {
                 _notifier.Notify(NotificationService.Triggers.SecurityZombieDetected,
                    "🧟 ZOMBIE DETECTED (Sans Licence)",
                    $"HardwareID: {hardwareId}\nIPs: {recentIps.Count}");
            }
        }
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