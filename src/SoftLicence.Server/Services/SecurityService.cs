using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using SoftLicence.Server.Data;
using System.Collections.Concurrent;
using System.Data;
using System.Net;
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
    private static readonly TimeSpan ZombieNotificationCooldown = TimeSpan.FromHours(24);
    private const long HardwareBanLockSalt = 999095;
    private const string ZombieWarningFamily = "zombie_warning";
    private const string ZombieCriticalFamily = "zombie_critical";

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

    /// <summary>
    /// Checks whether an exact IP address is protected from punitive security enforcement.
    /// This policy never grants authentication or authorization.
    /// </summary>
    public bool IsProtectedInfrastructureIp(string ip)
    {
        if (!TryParseCanonicalIpAddress(ip, out var candidate))
            return false;

        var configuredIps = _config["SecuritySettings:ProtectedInfrastructureIps"];
        if (string.IsNullOrWhiteSpace(configuredIps))
            return false;

        foreach (var configuredIp in configuredIps.Split(
                     ',',
                     StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (TryParseCanonicalIpAddress(configuredIp, out var configuredAddress)
                && candidate.Equals(configuredAddress))
            {
                return true;
            }
        }

        return false;
    }

    private static bool TryParseCanonicalIpAddress(string value, out IPAddress address)
    {
        if (!IPAddress.TryParse(value, out var parsed))
        {
            address = IPAddress.None;
            return false;
        }

        address = parsed.IsIPv4MappedToIPv6 ? parsed.MapToIPv4() : parsed;
        return true;
    }

    public async Task<bool> IsBannedAsync(string ip)
    {
        if (IsWhitelisted(ip) || IsProtectedInfrastructureIp(ip))
        {
            _bannedCache.TryRemove(ip, out _);
            _threatScores.TryRemove(ip, out _);
            return false;
        }

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
        if (IsWhitelisted(ip) || IsProtectedInfrastructureIp(ip))
            return 0;

        using var db = await _dbFactory.CreateDbContextAsync();
        var ban = await db.BannedIps.AsNoTracking().FirstOrDefaultAsync(b => b.IpAddress == ip);
        return ban?.BanCount ?? 0;
    }

    public async Task ReportThreatAsync(string ip, int points, string reason)
    {
        if (ip == "127.0.0.1" || ip == "::1" || ip == "Unknown") return;

        // Immunité : les IPs whitelisted ne sont jamais scorées.
        if (IsWhitelisted(ip)) return;

        // Infrastructure protection is deliberately distinct from admin authentication.
        // Requests remain rejected and audited, but cannot punish or ban our own services.
        if (IsProtectedInfrastructureIp(ip))
        {
            _logger.LogWarning(
                "Threat enforcement skipped for protected infrastructure IP {IP}: {Reason}",
                ip,
                reason);
            _threatScores.TryRemove(ip, out _);
            return;
        }

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
        if (IsWhitelisted(ip) || IsProtectedInfrastructureIp(ip))
            return 0;

        if (_threatScores.TryGetValue(ip, out var entry))
            return entry.Score;
        return 0;
    }

    public async Task BanIpAsync(string ip, string reason)
    {
        if (IsWhitelisted(ip)) return;
        if (IsProtectedInfrastructureIp(ip))
        {
            _logger.LogCritical(
                "IP ban suppressed for protected infrastructure IP {IP}: {Reason}",
                ip,
                reason);
            _bannedCache.TryRemove(ip, out _);
            _threatScores.TryRemove(ip, out _);
            return;
        }

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
        var canonicalHardwareId = CanonicalizeHardwareId(hardwareId);
        var now = DateTime.UtcNow;

        await using var db = await _dbFactory.CreateDbContextAsync();
        var hasLiveBan = await db.BannedHardwareIds.AsNoTracking().AnyAsync(b =>
            b.HardwareId.ToUpper() == canonicalHardwareId && b.IsActive &&
            (b.ProductId == null || !productId.HasValue || b.ProductId == productId) &&
            (b.ExpiresAt == null || b.ExpiresAt > now));
        if (hasLiveBan) return true;
        var hasExpiredActiveBan = await db.BannedHardwareIds.AsNoTracking().AnyAsync(b =>
            b.HardwareId.ToUpper() == canonicalHardwareId && b.IsActive &&
            (b.ProductId == null || !productId.HasValue || b.ProductId == productId));
        if (!hasExpiredActiveBan) return false;

        await using var mutationDb = await _dbFactory.CreateDbContextAsync();
        await using var transaction = await BeginHardwareBanMutationAsync(mutationDb, canonicalHardwareId);
        var current = await mutationDb.BannedHardwareIds.Where(candidate =>
                candidate.HardwareId.ToUpper() == canonicalHardwareId && candidate.IsActive &&
                (candidate.ProductId == null || !productId.HasValue || candidate.ProductId == productId))
            .ToListAsync();
        now = DateTime.UtcNow;
        if (current.Any(candidate => candidate.ExpiresAt == null || candidate.ExpiresAt > now)) return true;
        foreach (var expired in current) expired.IsActive = false;
        await mutationDb.SaveChangesAsync();
        if (transaction != null) await transaction.CommitAsync();
        return false;
    }

    public async Task<Data.BannedHardwareId?> GetActiveHardwareBanAsync(string hardwareId, Guid? productId = null)
    {
        if (string.IsNullOrEmpty(hardwareId)) return null;
        var canonicalHardwareId = CanonicalizeHardwareId(hardwareId);
        var now = DateTime.UtcNow;

        await using var db = await _dbFactory.CreateDbContextAsync();
        var ban = await db.BannedHardwareIds.AsNoTracking()
            .Where(b => b.HardwareId.ToUpper() == canonicalHardwareId && b.IsActive
                && (b.ProductId == null || !productId.HasValue || b.ProductId == productId)
                && (b.ExpiresAt == null || b.ExpiresAt > now))
            .OrderByDescending(b => b.BannedAt)
            .FirstOrDefaultAsync();

        if (ban != null) return ban;
        var hasExpiredActiveBan = await db.BannedHardwareIds.AsNoTracking().AnyAsync(b =>
            b.HardwareId.ToUpper() == canonicalHardwareId && b.IsActive
            && (b.ProductId == null || !productId.HasValue || b.ProductId == productId));
        if (!hasExpiredActiveBan) return null;

        await using var mutationDb = await _dbFactory.CreateDbContextAsync();
        await using var transaction = await BeginHardwareBanMutationAsync(mutationDb, canonicalHardwareId);
        var current = await mutationDb.BannedHardwareIds.Where(candidate =>
                candidate.HardwareId.ToUpper() == canonicalHardwareId && candidate.IsActive
                && (candidate.ProductId == null || !productId.HasValue || candidate.ProductId == productId))
            .OrderByDescending(candidate => candidate.BannedAt)
            .ToListAsync();
        now = DateTime.UtcNow;
        var renewed = current.FirstOrDefault(candidate =>
            candidate.ExpiresAt == null || candidate.ExpiresAt > now);
        if (renewed != null) return renewed;
        foreach (var expired in current) expired.IsActive = false;
        await mutationDb.SaveChangesAsync();
        if (transaction != null) await transaction.CommitAsync();
        return null;
    }

    public async Task BanHardwareIdAsync(string hardwareId, string reason, Guid? productId = null, DateTime? expiresAt = null, Guid? piracySuspectId = null, string? banCategory = null, bool silent = false)
    {
        if (string.IsNullOrEmpty(hardwareId)) return;
        hardwareId = CanonicalizeHardwareId(hardwareId);
        banCategory ??= Data.BannedHardwareId.Categories.Manual;
        if (!Data.BannedHardwareId.Categories.IsKnown(banCategory))
            throw new ArgumentException(
                "ban_category_invalid: banCategory must be an exact known category identifier.",
                nameof(banCategory));

        using var db = await _dbFactory.CreateDbContextAsync();
        await using var transaction = await BeginHardwareBanMutationAsync(db, hardwareId);

        // Check if HWID is whitelisted/greylisted (immune to auto-ban)
        bool isProtected = false;
        if (reason.StartsWith("Auto-ban:"))
        {
            var listType = await db.HardwareFingerprints.AsNoTracking()
                .Where(f => f.HardwareId.ToUpper() == hardwareId)
                .Select(f => f.ListType)
                .FirstOrDefaultAsync();
            if (listType == "white" || listType == "grey")
                isProtected = true;
        }

        var existing = await db.BannedHardwareIds.FirstOrDefaultAsync(b =>
            b.HardwareId.ToUpper() == hardwareId &&
            b.ProductId == productId);

        if (existing != null)
        {
            // Record the entry but set inactive if protected (keep history)
            existing.IsActive = !isProtected;
            existing.HardwareId = hardwareId;
            existing.Reason = isProtected ? $"[PROTECTED:{reason}]" : reason;
            existing.BannedAt = DateTime.UtcNow;
            existing.ExpiresAt = expiresAt;
            existing.BanCategory = banCategory;
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
        if (transaction != null) await transaction.CommitAsync();

        if (isProtected)
        {
            _logger.LogInformation("HWID {HardwareId} protected (whitelist/greylist) - entry saved inactive: {Reason}", hardwareId, reason);
            return;
        }

        _logger.LogCritical("HARDWARE ID BANNI{Silent} : {HardwareId} pour {Reason}",
            silent ? " [SILENT]" : "", hardwareId, reason);
        if (!silent)
            _notifier.Notify(NotificationService.Triggers.SecurityIpBanned,
                "HARDWARE ID BANNI",
                $"HWID: {hardwareId}\nRaison: {reason}");
    }

    public async Task<bool> UnbanHardwareIdAsync(Guid banId, string? auditReason = null)
    {
        string? hardwareId;
        await using (var lookupDb = await _dbFactory.CreateDbContextAsync())
        {
            hardwareId = await lookupDb.BannedHardwareIds.AsNoTracking()
                .Where(candidate => candidate.Id == banId)
                .Select(candidate => candidate.HardwareId)
                .SingleOrDefaultAsync();
        }
        if (hardwareId == null) return false;

        using var db = await _dbFactory.CreateDbContextAsync();
        await using var transaction = await BeginHardwareBanMutationAsync(db, hardwareId);
        var ban = await db.BannedHardwareIds.FindAsync(banId);
        if (ban == null) return false;
        if (!ban.IsActive) return true;

        ban.IsActive = false;
        AppendUnbanAudit(ban, auditReason);
        await db.SaveChangesAsync();
        if (transaction != null) await transaction.CommitAsync();

        _logger.LogInformation("HARDWARE ID DEBANNI : {HardwareId}", ban.HardwareId);
        return true;
    }

    /// <summary>
    /// Auto-unban a HWID that was auto-banned for version violation, if they updated.
    /// Only unbans version-enforcement entries with the exact outdated_version category
    /// and the automatic-ban reason marker. Any other applicable active ban fails closed.
    /// </summary>
    public async Task<bool> AutoUnbanByHwidAsync(string hardwareId, Guid productId)
    {
        if (string.IsNullOrEmpty(hardwareId)) return false;
        hardwareId = CanonicalizeHardwareId(hardwareId);

        using var db = await _dbFactory.CreateDbContextAsync();
        await using var transaction = await BeginHardwareBanMutationAsync(db, hardwareId);
        var bans = await db.BannedHardwareIds
            .Where(b => b.HardwareId.ToUpper() == hardwareId && b.IsActive
                && (b.ProductId == null || b.ProductId == productId)
                && (b.ExpiresAt == null || b.ExpiresAt > DateTime.UtcNow))
            .ToListAsync();

        if (bans.Count == 0) return false;

        var allEligible = bans.All(ban =>
            string.Equals(
                ban.BanCategory,
                Data.BannedHardwareId.Categories.OutdatedVersion,
                StringComparison.Ordinal)
            && ban.Reason.StartsWith("Auto-ban:", StringComparison.Ordinal));
        if (!allEligible)
        {
            _logger.LogInformation(
                "Version auto-unban blocked for {HardwareId}: at least one applicable ban is not exact outdated_version authority.",
                hardwareId);
            return false;
        }

        foreach (var ban in bans) ban.IsActive = false;

        await db.SaveChangesAsync();
        if (transaction != null) await transaction.CommitAsync();

        _logger.LogWarning("AUTO-UNBAN: {HardwareId} (updated to compliant version). {BanCount} hardware ban(s) lifted.",
            hardwareId, bans.Count);

        _notifier.Notify(NotificationService.Triggers.SecurityIpBanned,
            "AUTO-UNBAN VERSION",
            $"HWID: {hardwareId}\nMis à jour vers version conforme.\n{bans.Count} ban(s) HWID levé(s). Les bans composants restent sous autorité opérateur.");

        return true;
    }

    public sealed record DeferredNotification(string Trigger, string Title, string Message);

    public sealed record PaidAutoUnbanDecision(
        bool CanProceed,
        bool PermanentBan,
        DeferredNotification? Notification);

    /// <summary>
    /// Stages an eligible paid-license auto-unban in the caller's activation transaction.
    /// The caller owns SaveChanges, commit/rollback, and deferred notification delivery.
    /// </summary>
    public async Task<PaidAutoUnbanDecision> TryAutoUnbanForPaidLicenseAsync(
        LicenseDbContext db,
        string hardwareId,
        Guid productId)
    {
        if (string.IsNullOrEmpty(hardwareId)) return new(true, false, null);
        hardwareId = CanonicalizeHardwareId(hardwareId);

        await AcquireHardwareBanMutationAsync(db, hardwareId);
        var activeBans = await db.BannedHardwareIds
            .Where(b => b.HardwareId.ToUpper() == hardwareId && b.IsActive
                && (b.ProductId == null || b.ProductId == productId)
                && (b.ExpiresAt == null || b.ExpiresAt > DateTime.UtcNow))
            .ToListAsync();

        if (activeBans.Count == 0) return new(true, false, null);

        // Check if any ban is permanent (debugger, piracy)
        var hasPermanent = activeBans.Any(b =>
            Data.BannedHardwareId.Categories.IsPermanent(b.BanCategory));
        if (hasPermanent)
        {
            _logger.LogWarning("Paid activation blocked for {HardwareId}: permanent ban ({Categories})",
                hardwareId, string.Join(", ", activeBans.Where(b => Data.BannedHardwareId.Categories.IsPermanent(b.BanCategory)).Select(b => b.BanCategory)));
            return new(false, true, null);
        }

        var hasIneligible = activeBans.Any(b =>
            !Data.BannedHardwareId.Categories.IsAutoUnbannable(b.BanCategory));
        if (hasIneligible)
        {
            _logger.LogInformation(
                "Paid activation blocked for {HardwareId}: at least one category is outside the exact auto-unban allowlist.",
                hardwareId);
            return new(false, false, null);
        }

        // All remaining bans are auto-unbannable (quota_abuse, outdated_version)
        foreach (var ban in activeBans)
        {
            ban.IsActive = false;
        }

        var categories = activeBans
            .Select(b => b.BanCategory ?? Data.BannedHardwareId.Categories.Manual)
            .Distinct(StringComparer.Ordinal)
            .ToList();
        var isOutdatedOnly = categories.Count == 1
            && categories[0] == Data.BannedHardwareId.Categories.OutdatedVersion;
        var title = isOutdatedOnly
            ? "AUTO-UNBAN VERSION OBSOLETE"
            : "AUTO-UNBAN LICENCE PAYANTE";
        var reason = isOutdatedOnly
            ? "Déblocage d'un ban version obsolète sur licence payante valide."
            : "Activation licence payante valide.";

        var notification = new DeferredNotification(
            NotificationService.Triggers.SecurityIpBanned,
            title,
            $"HWID: {hardwareId}\n{reason}\n{activeBans.Count} ban(s) levé(s) (catégories: {string.Join(", ", categories)}).");

        return new(true, false, notification);
    }

    private static async Task<IDbContextTransaction?> BeginHardwareBanMutationAsync(
        LicenseDbContext db,
        string hardwareId)
    {
        if (!db.Database.IsRelational()) return null;

        var transaction = await db.Database.BeginTransactionAsync(
            db.Database.IsNpgsql() ? IsolationLevel.ReadCommitted : IsolationLevel.Serializable);
        try
        {
            await AcquireHardwareBanMutationAsync(db, hardwareId);
            return transaction;
        }
        catch
        {
            await transaction.RollbackAsync();
            await transaction.DisposeAsync();
            throw;
        }
    }

    private static async Task AcquireHardwareBanMutationAsync(
        LicenseDbContext db,
        string hardwareId)
    {
        if (!db.Database.IsRelational()) return;
        if (db.Database.CurrentTransaction == null)
            throw new InvalidOperationException(
                "The hardware-ban authority lock requires the caller's active transaction.");
        if (!db.Database.IsNpgsql()) return;

        var lockKey = $"hardware-ban-v1|{CanonicalizeHardwareId(hardwareId)}";
        await db.Database.ExecuteSqlRawAsync(
            "SET LOCAL lock_timeout = '5000ms'; SET LOCAL statement_timeout = '30000ms';");
        await db.Database.ExecuteSqlInterpolatedAsync(
            $"SELECT pg_advisory_xact_lock(hashtextextended({lockKey}, {HardwareBanLockSalt}))");
    }

    private static string CanonicalizeHardwareId(string hardwareId) => hardwareId.ToUpperInvariant();

    public async Task<List<Data.BannedHardwareId>> GetBannedHardwareIdsAsync()
    {
        using var db = await _dbFactory.CreateDbContextAsync();
        return await db.BannedHardwareIds
            .Include(b => b.Product)
            .OrderByDescending(b => b.BannedAt)
            .ToListAsync();
    }

    public async Task CheckForZombieAsync(
        string hardwareId,
        string currentIp,
        string endpoint = "CHECK",
        string resultStatus = "OK")
    {
        // Contractual SDK HWIDs are exactly 16 uppercase ASCII hexadecimal characters.
        // Legacy display values such as "8A96631C..." must never become security identities.
        if (!IsCanonicalHardwareId(hardwareId)) return;
        if (IsWhitelisted(currentIp)) return;
        if (!IsAuthoritativeSuccessfulLicenseAccess(endpoint, resultStatus)) return;

        using var db = await _dbFactory.CreateDbContextAsync();

        // Skip whitelisted/greylisted HWIDs
        var listType = await db.HardwareFingerprints.AsNoTracking()
            .Where(f => f.HardwareId == hardwareId)
            .Select(f => f.ListType)
            .FirstOrDefaultAsync();
        if (listType == "white" || listType == "grey") return;

        // Zombie detection protects only an active paid multi-seat entitlement. A process
        // without such a licence cannot share licence capacity and belongs to another signal.
        var activeLicense = await db.Licenses
            .Include(l => l.Type)
            .Include(l => l.Product)
            .FirstOrDefaultAsync(l => l.IsActive
                && l.Type != null
                && !l.Type.IsFree
                && l.Type.DefaultMaxSeats > 1
                && (l.HardwareId == hardwareId || l.Seats.Any(s => s.HardwareId == hardwareId)));

        if (activeLicense == null) return;

        var now = DateTime.UtcNow;
        var recentIps = await db.AccessLogs
            .Where(l => l.HardwareId == hardwareId
                && l.Timestamp > now.AddHours(-24)
                && (l.Endpoint == "CHECK" || l.Endpoint == "ACTIVATE")
                && (l.ResultStatus == "OK" || l.ResultStatus == "CREATED"))
            .Select(l => l.ClientIp)
            .Distinct()
            .ToListAsync();

        if (IsCountablePublicIp(currentIp) && !recentIps.Contains(currentIp, StringComparer.Ordinal))
            recentIps.Add(currentIp);

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

        // PALIER 1 — ALERTE : Plus de 5 sous-réseaux /24 distincts en 24h → notification de surveillance
        if (distinctSubnets > 5 && distinctSubnets <= 8)
        {
            _logger.LogWarning("ZOMBIE WARNING : HardwareID {Hwid} seen on {Count} IPs across {Subnets} subnets (surveillance)", hardwareId, recentIps.Count, distinctSubnets);

            if (await TryReserveZombieNotificationAsync(
                activeLicense.ProductId, hardwareId, ZombieWarningFamily, 3, now, recentIps))
            {
                _notifier.Notify(NotificationService.Triggers.SecurityZombieDetected,
                    "⚠️ ZOMBIE WARNING (Surveillance)",
                    BuildZombieMessage(hardwareId, recentIps, distinctSubnets, activeLicense, false));
            }
        }

        // PALIER 2 — ALERTE CRITIQUE : Plus de 8 sous-réseaux distincts en 24h → alerte sans révocation auto
        if (distinctSubnets > 8)
        {
            _logger.LogCritical("ZOMBIE DETECTED : HardwareID {Hwid} seen on {Count} IPs across {Subnets} subnets!", hardwareId, recentIps.Count, distinctSubnets);

            if (await TryReserveZombieNotificationAsync(
                activeLicense.ProductId, hardwareId, ZombieCriticalFamily, 4, now, recentIps))
            {
                _notifier.Notify(NotificationService.Triggers.SecurityZombieDetected,
                    "🧟 ZOMBIE DETECTED (Action manuelle requise)",
                    BuildZombieMessage(hardwareId, recentIps, distinctSubnets, activeLicense, true));
            }
        }
    }

    internal static bool IsCanonicalHardwareId(string? hardwareId) =>
        hardwareId is { Length: 16 }
        && hardwareId.All(c => c is >= '0' and <= '9' or >= 'A' and <= 'F');

    internal static bool IsAuthoritativeSuccessfulLicenseAccess(string endpoint, string resultStatus) =>
        (endpoint == "CHECK" || endpoint == "ACTIVATE")
        && (resultStatus == "OK" || resultStatus == "CREATED");

    private static bool IsCountablePublicIp(string ip) =>
        ip != "Unknown"
        && ip != "127.0.0.1"
        && System.Net.IPAddress.TryParse(ip, out _);

    private static string BuildZombieMessage(
        string hardwareId,
        IReadOnlyCollection<string> recentIps,
        int distinctSubnets,
        License activeLicense,
        bool critical)
    {
        return $"HardwareID: {hardwareId}\n"
            + $"Produit: {activeLicense.Product?.Name ?? activeLicense.ProductId.ToString("D")}\n"
            + "Licence: active, payante, multi-sièges\n"
            + $"Source: AccessLogs, fenêtre glissante 24 h\n"
            + $"IPs: {recentIps.Count} ({distinctSubnets} sous-réseaux)\n"
            + "Détails contributeurs: preuves internes de l’incident SecurityIncidents\n"
            + (critical ? "Seuil critique confirmé — vérification manuelle requise." : "Seuil de surveillance confirmé — aucune révocation automatique.");
    }

    private async Task<bool> TryReserveZombieNotificationAsync(
        Guid productId,
        string hardwareId,
        string family,
        int severity,
        DateTime observedAt,
        IReadOnlyCollection<string> recentIps)
    {
        const int maxAttempts = 3;
        for (var attempt = 1; attempt <= maxAttempts; attempt++)
        {
            try
            {
                await using var db = await _dbFactory.CreateDbContextAsync();
                await using var transaction = db.Database.IsRelational()
                    ? await db.Database.BeginTransactionAsync(
                        db.Database.IsNpgsql() ? IsolationLevel.ReadCommitted : IsolationLevel.Serializable)
                    : null;

                if (db.Database.IsNpgsql())
                {
                    var lockKey = $"zombie-notification-v1|{productId:D}|{hardwareId}";
                    await db.Database.ExecuteSqlInterpolatedAsync(
                        $"SELECT pg_advisory_xact_lock(hashtextextended({lockKey}, 999883))");
                }

                var latest = await db.SecurityIncidents
                    .Where(row => row.ProductId == productId
                        && row.HardwareId == hardwareId
                        && (row.Family == ZombieWarningFamily || row.Family == ZombieCriticalFamily)
                        && row.InitialNotificationSentAtUtc != null)
                    .OrderByDescending(row => row.InitialNotificationSentAtUtc)
                    .FirstOrDefaultAsync();

                if (latest?.InitialNotificationSentAtUtc is DateTime lastNotification
                    && observedAt - lastNotification < ZombieNotificationCooldown
                    && latest.Severity >= severity)
                {
                    if (transaction != null) await transaction.CommitAsync();
                    return false;
                }

                var incident = new SecurityIncident
                {
                    ProductId = productId,
                    HardwareId = hardwareId,
                    Family = family,
                    Severity = severity,
                    WindowStartUtc = observedAt,
                    WindowEndUtc = observedAt.AddHours(24),
                    FirstSeenUtc = observedAt,
                    LastSeenUtc = observedAt,
                    OccurrenceCount = 1,
                    IsHardwareBanned = false,
                    InitialNotificationSentAtUtc = observedAt
                };
                foreach (var evidence in BuildZombieEvidence(recentIps, observedAt))
                    incident.Evidence.Add(evidence);
                db.SecurityIncidents.Add(incident);
                await db.SaveChangesAsync();
                if (transaction != null) await transaction.CommitAsync();
                return true;
            }
            catch (Exception exception) when (attempt < maxAttempts && IsZombieReservationConflict(exception))
            {
                await Task.Delay(TimeSpan.FromMilliseconds(10 * attempt));
            }
        }

        throw new InvalidOperationException("Zombie notification reservation retry loop exhausted unexpectedly.");
    }

    private static IEnumerable<SecurityIncidentEvidence> BuildZombieEvidence(
        IEnumerable<string> recentIps,
        DateTime observedAt)
    {
        var ips = recentIps
            .Where(ip => System.Net.IPAddress.TryParse(ip, out _))
            .Distinct(StringComparer.Ordinal)
            .OrderBy(value => value, StringComparer.Ordinal)
            .Take(100);
        foreach (var ip in ips)
        {
            yield return new SecurityIncidentEvidence
            {
                ComponentType = "IP",
                ComponentHash = ip,
                FirstSeenUtc = observedAt,
                LastSeenUtc = observedAt,
                OccurrenceCount = 1
            };
        }
    }

    private static bool IsZombieReservationConflict(Exception exception)
    {
        var postgres = EnumerateExceptionChain(exception).OfType<PostgresException>().FirstOrDefault();
        return postgres?.SqlState is PostgresErrorCodes.SerializationFailure
            or PostgresErrorCodes.DeadlockDetected
            or PostgresErrorCodes.UniqueViolation;
    }

    private static IEnumerable<Exception> EnumerateExceptionChain(Exception exception)
    {
        for (var current = exception; current != null; current = current.InnerException)
            yield return current;
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

    /// <summary>
    /// Only signed release-binary fingerprints are safe global enforcement targets.
    /// Hardware component values are correlation hints: virtual machines and cloned
    /// images can legitimately expose the same CPU, motherboard, BIOS, disk or host value.
    /// </summary>
    public static bool IsEnforceableComponentType(string? componentType)
    {
        if (string.IsNullOrWhiteSpace(componentType)) return false;
        return NormalizeComponentType(componentType) is "FP_EXE" or "FP_DLL" or "FP_CORE";
    }

    public static bool TryNormalizeComponentHash(string? componentHash, out string normalizedHash)
    {
        normalizedHash = componentHash?.Trim().ToLowerInvariant() ?? string.Empty;
        return normalizedHash.Length == 64
            && normalizedHash.All(character => character is >= '0' and <= '9' or >= 'a' and <= 'f');
    }

    public async Task<(bool IsBanned, string ComponentType, string Reason)> IsComponentBannedAsync(Dictionary<string, string> fingerprints, Guid? productId = null)
    {
        if (fingerprints == null || fingerprints.Count == 0)
            return (false, "", "");

        var componentMap = new Dictionary<string, string>
        {
            ["FP_EXE"] = "FP_EXE",
            ["FP_DLL"] = "FP_DLL",
            ["FP_CORE"] = "FP_CORE"
        };

        // Check cache first
        foreach (var (key, type) in componentMap)
        {
            var hash = fingerprints.FirstOrDefault(pair =>
                string.Equals(pair.Key, key, StringComparison.OrdinalIgnoreCase)).Value;
            if (!TryNormalizeComponentHash(hash, out var normalizedHash)) continue;
            var cacheKey = $"comp:{type}:{normalizedHash}:{productId}";
            if (_bannedComponentCache.TryGetValue(cacheKey, out var cachedAt) && DateTime.UtcNow - cachedAt < ComponentCacheTtl)
                return (true, type, "Cached ban");
        }

        using var db = await _dbFactory.CreateDbContextAsync();

        foreach (var (key, type) in componentMap)
        {
            var hash = fingerprints.FirstOrDefault(pair =>
                string.Equals(pair.Key, key, StringComparison.OrdinalIgnoreCase)).Value;
            if (!TryNormalizeComponentHash(hash, out var normalizedHash)) continue;

            var candidates = await db.BannedComponents.Where(b =>
                    b.ComponentType == type && b.IsActive &&
                    (b.ProductId == null || b.ProductId == productId))
                .ToListAsync();
            var ban = candidates.FirstOrDefault(candidate =>
                TryNormalizeComponentHash(candidate.ComponentHash, out var candidateHash)
                && string.Equals(candidateHash, normalizedHash, StringComparison.Ordinal));

            if (ban != null)
            {
                if (ban.ExpiresAt == null || ban.ExpiresAt > DateTime.UtcNow)
                {
                    var cacheKey = $"comp:{type}:{normalizedHash}:{productId}";
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
        if (string.IsNullOrWhiteSpace(componentType))
            throw new ArgumentException("component_type_invalid: componentType is required.", nameof(componentType));

        componentType = NormalizeComponentType(componentType);

        if (!TryNormalizeComponentHash(componentHash, out var normalizedHash))
            throw new ArgumentException(
                "component_hash_invalid: componentHash must be exactly 64 ASCII hexadecimal characters.",
                nameof(componentHash));
        componentHash = normalizedHash;

        if (!IsEnforceableComponentType(componentType))
            throw new InvalidOperationException(
                "hardware_component_not_enforceable: CPU, MB, BIOS, DISK and HOST fingerprints are correlation-only and cannot be globally banned.");

        using var db = await _dbFactory.CreateDbContextAsync();

        var existingCandidates = await db.BannedComponents.Where(b =>
                b.ComponentType == componentType &&
                b.ProductId == productId)
            .ToListAsync();
        var existing = existingCandidates.FirstOrDefault(candidate =>
            TryNormalizeComponentHash(candidate.ComponentHash, out var candidateHash)
            && string.Equals(candidateHash, componentHash, StringComparison.Ordinal));

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

    public async Task<bool> UnbanComponentAsync(Guid banId, string? auditReason = null)
    {
        using var db = await _dbFactory.CreateDbContextAsync();
        var ban = await db.BannedComponents.FindAsync(banId);
        if (ban == null) return false;

        ban.IsActive = false;
        AppendUnbanAudit(ban, auditReason);
        await db.SaveChangesAsync();

        var cacheKey = $"comp:{ban.ComponentType}:{ban.ComponentHash}:{ban.ProductId}";
        _bannedComponentCache.TryRemove(cacheKey, out _);

        _logger.LogInformation("COMPONENT UNBANNED: {Type}={Hash}", ban.ComponentType, ban.ComponentHash);
        return true;
    }

    private static void AppendUnbanAudit(object ban, string? auditReason)
    {
        if (string.IsNullOrWhiteSpace(auditReason)) return;

        const int maxReasonLength = 500;
        var entry = $"unban={DateTime.UtcNow:O} | {auditReason.Trim()}";
        string current;
        switch (ban)
        {
            case BannedHardwareId hardware:
                current = hardware.Reason;
                hardware.Reason = JoinBoundedAuditReason(current, entry, maxReasonLength);
                break;
            case BannedComponent component:
                current = component.Reason;
                component.Reason = JoinBoundedAuditReason(current, entry, maxReasonLength);
                break;
        }
    }

    private static string JoinBoundedAuditReason(string? current, string entry, int maxLength)
    {
        if (entry.Length >= maxLength) return entry[..maxLength];
        if (string.IsNullOrWhiteSpace(current)) return entry;

        const string separator = " | ";
        var availableForOriginal = maxLength - entry.Length - separator.Length;
        var original = current.Trim();
        if (original.Length > availableForOriginal)
            original = original[..availableForOriginal];
        return $"{original}{separator}{entry}";
    }

    public async Task<List<BannedComponent>> GetBannedComponentsAsync(Guid? scopedProductId = null)
    {
        using var db = await _dbFactory.CreateDbContextAsync();
        return await db.BannedComponents
            .Include(b => b.Product)
            .Where(b => b.IsActive && (!scopedProductId.HasValue
                || b.ProductId == null
                || b.ProductId == scopedProductId))
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
