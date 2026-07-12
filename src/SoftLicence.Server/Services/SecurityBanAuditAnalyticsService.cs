using Microsoft.EntityFrameworkCore;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;

namespace SoftLicence.Server.Services;

public sealed class SecurityBanAuditAnalyticsService
{
    private const int DefaultTake = 25;
    private const int MaxTake = 100;
    private static readonly TimeSpan NearSourceWindow = TimeSpan.FromMinutes(10);
    private static readonly TimeSpan FallbackSourceWindow = TimeSpan.FromHours(24);

    private readonly IDbContextFactory<LicenseDbContext> _dbFactory;

    public SecurityBanAuditAnalyticsService(IDbContextFactory<LicenseDbContext> dbFactory)
    {
        _dbFactory = dbFactory;
    }

    public async Task<SecurityBanAuditResponse> ListBansForProductIdAsync(
        Guid productId,
        string? hardwareId,
        string? componentHash,
        string? componentType,
        string? clientIp,
        string? emailFragment,
        string? licenseFragment,
        bool includeInactive,
        int take = DefaultTake,
        CancellationToken cancellationToken = default)
    {
        take = Math.Clamp(take, 1, MaxTake);
        var criteria = NormalizeCriteria(hardwareId, componentHash, componentType, clientIp, emailFragment, licenseFragment);

        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        var productScopeIds = await ProductScopeResolver.ResolveProductScopeIdsAsync(db, productId, cancellationToken);
        var candidateHwids = await ResolveCandidateHardwareIdsAsync(db, productScopeIds, criteria, cancellationToken);
        var candidateHashes = await ResolveCandidateComponentHashesAsync(db, productId, criteria, candidateHwids, cancellationToken);

        var items = new List<SecurityBanAuditItem>();
        items.AddRange(await QueryHardwareBansAsync(db, productScopeIds, criteria, candidateHwids, includeInactive, cancellationToken));
        items.AddRange(await QueryComponentBansAsync(db, productScopeIds, criteria, candidateHashes, includeInactive, cancellationToken));

        var ordered = items
            .OrderByDescending(i => i.IsActive)
            .ThenByDescending(i => i.BannedAtUtc)
            .ThenBy(i => i.TargetType, StringComparer.OrdinalIgnoreCase)
            .ThenBy(i => i.ComponentType, StringComparer.OrdinalIgnoreCase)
            .ToList();

        var returned = ordered.Take(take).ToList();
        return new SecurityBanAuditResponse
        {
            Query = new SecurityBanAuditQuery
            {
                HasHardwareId = criteria.HardwareId != null,
                HasComponentHash = criteria.ComponentHash != null,
                HasComponentType = criteria.ComponentType != null,
                HasClientIp = criteria.ClientIp != null,
                HasEmailFragment = criteria.EmailFragment != null,
                HasLicenseFragment = criteria.LicenseFragment != null,
                IncludeInactive = includeInactive,
                Take = take
            },
            RecordsMatched = ordered.Count,
            RecordsReturned = returned.Count,
            Bans = returned
        };
    }

    public async Task<SecurityBanDetailsResponse> GetBanDetailsForProductIdAsync(
        Guid productId,
        Guid banId,
        CancellationToken cancellationToken = default)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        var productScopeIds = await ProductScopeResolver.ResolveProductScopeIdsAsync(db, productId, cancellationToken);

        var hardwareBan = await db.BannedHardwareIds.AsNoTracking()
            .Include(b => b.Product)
            .FirstOrDefaultAsync(b => b.Id == banId && (b.ProductId == null || productScopeIds.Contains(b.ProductId.Value)), cancellationToken);
        if (hardwareBan != null)
        {
            var item = MapHardwareBan(hardwareBan, "ban_id");
            var source = await FindSourceEventAsync(db, productScopeIds, item, cancellationToken);
            ApplySourceSummary(item, source);
            return new SecurityBanDetailsResponse { Ban = item, SourceEvent = source };
        }

        var componentBan = await db.BannedComponents.AsNoTracking()
            .Include(b => b.Product)
            .FirstOrDefaultAsync(b => b.Id == banId && (b.ProductId == null || productScopeIds.Contains(b.ProductId.Value)), cancellationToken);
        if (componentBan != null)
        {
            var item = MapComponentBan(componentBan, "ban_id");
            var source = await FindSourceEventAsync(db, productScopeIds, item, cancellationToken);
            ApplySourceSummary(item, source);
            return new SecurityBanDetailsResponse { Ban = item, SourceEvent = source };
        }

        return new SecurityBanDetailsResponse
        {
            SourceEvent = new SecurityBanSourceEvent
            {
                Found = false,
                Status = "ban_not_found",
                SearchStrategy = "ban_id"
            }
        };
    }

    public async Task<SecurityBanSourceEvent> GetBanSourceEventForProductIdAsync(
        Guid productId,
        Guid banId,
        CancellationToken cancellationToken = default)
    {
        var details = await GetBanDetailsForProductIdAsync(productId, banId, cancellationToken);
        return details.SourceEvent ?? new SecurityBanSourceEvent
        {
            Found = false,
            Status = "source_not_checked",
            SearchStrategy = "ban_id"
        };
    }

    private static async Task<List<SecurityBanAuditItem>> QueryHardwareBansAsync(
        LicenseDbContext db,
        List<Guid> productScopeIds,
        SearchCriteria criteria,
        HashSet<string> candidateHwids,
        bool includeInactive,
        CancellationToken cancellationToken)
    {
        var query = db.BannedHardwareIds.AsNoTracking()
            .Include(b => b.Product)
            .Where(b => b.ProductId == null || productScopeIds.Contains(b.ProductId.Value));

        if (!includeInactive)
            query = query.Where(b => b.IsActive);

        if (candidateHwids.Count > 0)
            query = query.Where(b => candidateHwids.Contains(b.HardwareId));
        else if (criteria.HardwareId != null)
            query = query.Where(b => b.HardwareId.ToUpper().Contains(criteria.HardwareId));
        else if (HasOnlyComponentCriteria(criteria))
            return new List<SecurityBanAuditItem>();

        var bans = await query
            .OrderByDescending(b => b.BannedAt)
            .Take(MaxTake)
            .ToListAsync(cancellationToken);

        return bans
            .Select(b => MapHardwareBan(b, candidateHwids.Count > 0 ? "resolved_hardware_id" : "hardware_id"))
            .ToList();
    }

    private static async Task<List<SecurityBanAuditItem>> QueryComponentBansAsync(
        LicenseDbContext db,
        List<Guid> productScopeIds,
        SearchCriteria criteria,
        HashSet<string> candidateHashes,
        bool includeInactive,
        CancellationToken cancellationToken)
    {
        var query = db.BannedComponents.AsNoTracking()
            .Include(b => b.Product)
            .Where(b => b.ProductId == null || productScopeIds.Contains(b.ProductId.Value));

        if (!includeInactive)
            query = query.Where(b => b.IsActive);

        if (criteria.ComponentType != null)
            query = query.Where(b => b.ComponentType == criteria.ComponentType);

        if (candidateHashes.Count > 0)
            query = query.Where(b => candidateHashes.Contains(b.ComponentHash));
        else if (criteria.ComponentHash != null)
            query = query.Where(b => b.ComponentHash.ToUpper().Contains(criteria.ComponentHash));
        else if (criteria.HardwareId != null || criteria.ClientIp != null || criteria.EmailFragment != null || criteria.LicenseFragment != null)
            return new List<SecurityBanAuditItem>();

        var bans = await query
            .OrderByDescending(b => b.BannedAt)
            .Take(MaxTake)
            .ToListAsync(cancellationToken);

        return bans
            .Select(b => MapComponentBan(b, candidateHashes.Count > 0 ? "resolved_component_hash" : "component"))
            .ToList();
    }

    private static async Task<HashSet<string>> ResolveCandidateHardwareIdsAsync(
        LicenseDbContext db,
        List<Guid> productScopeIds,
        SearchCriteria criteria,
        CancellationToken cancellationToken)
    {
        var hwids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (criteria.HardwareId != null)
        {
            var fromTelemetry = await db.TelemetryRecords.AsNoTracking()
                .Where(r => r.ProductId.HasValue && productScopeIds.Contains(r.ProductId.Value) && r.HardwareId.ToUpper().Contains(criteria.HardwareId))
                .Select(r => r.HardwareId)
                .Distinct()
                .Take(MaxTake)
                .ToListAsync(cancellationToken);
            foreach (var hwid in fromTelemetry)
                hwids.Add(hwid);

            hwids.Add(criteria.HardwareId);
        }

        if (criteria.ClientIp != null)
        {
            var fromIp = await db.TelemetryRecords.AsNoTracking()
                .Where(r => r.ProductId.HasValue && productScopeIds.Contains(r.ProductId.Value) && r.ClientIp == criteria.ClientIp)
                .Select(r => r.HardwareId)
                .Distinct()
                .Take(MaxTake)
                .ToListAsync(cancellationToken);
            foreach (var hwid in fromIp)
                hwids.Add(hwid);
        }

        if (criteria.EmailFragment != null || criteria.LicenseFragment != null)
        {
            var licenses = db.Licenses.AsNoTracking()
                .Include(l => l.Seats)
                .Where(l => productScopeIds.Contains(l.ProductId));

            if (criteria.EmailFragment != null)
                licenses = licenses.Where(l => l.CustomerEmail.ToLower().Contains(criteria.EmailFragment));

            if (criteria.LicenseFragment != null)
            {
                var fragment = criteria.LicenseFragment;
                licenses = licenses.Where(l => l.LicenseKey.Replace("-", "").Replace(" ", "").ToUpper().Contains(fragment));
            }

            var rows = await licenses.Take(MaxTake).ToListAsync(cancellationToken);
            foreach (var license in rows)
            foreach (var resolved in LicenseSeatHardwareResolver.ResolveActiveHardwareIds(license))
                hwids.Add(resolved.HardwareId);
        }

        return hwids;
    }

    private static async Task<HashSet<string>> ResolveCandidateComponentHashesAsync(
        LicenseDbContext db,
        Guid productId,
        SearchCriteria criteria,
        HashSet<string> candidateHwids,
        CancellationToken cancellationToken)
    {
        var hashes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (criteria.ComponentHash != null)
            hashes.Add(criteria.ComponentHash);

        if (candidateHwids.Count == 0)
            return hashes;

        var fingerprints = await db.HardwareFingerprints.AsNoTracking()
            .Where(f => candidateHwids.Contains(f.HardwareId))
            .Take(MaxTake)
            .ToListAsync(cancellationToken);

        foreach (var fingerprint in fingerprints)
        {
            AddHash(hashes, fingerprint.CpuHash);
            AddHash(hashes, fingerprint.MotherboardHash);
            AddHash(hashes, fingerprint.BiosHash);
            AddHash(hashes, fingerprint.DiskHash);
            AddHash(hashes, fingerprint.HostHash);
        }

        return hashes;
    }

    private static async Task<SecurityBanSourceEvent> FindSourceEventAsync(
        LicenseDbContext db,
        List<Guid> productScopeIds,
        SecurityBanAuditItem item,
        CancellationToken cancellationToken)
    {
        IQueryable<TelemetryRecord> query = db.TelemetryRecords.AsNoTracking()
            .Include(r => r.EventData)
            .Where(r => r.ProductId.HasValue && productScopeIds.Contains(r.ProductId.Value));

        var strategy = "none";
        if (!string.IsNullOrWhiteSpace(item.ComponentHash))
        {
            var hash = item.ComponentHash;
            query = query.Where(r => r.EventData != null
                && r.EventData.PropertiesJson != null
                && r.EventData.PropertiesJson.Contains(hash));
            strategy = "component_hash_in_telemetry_properties";
        }
        else if (!string.IsNullOrWhiteSpace(item.HardwareId))
        {
            query = query.Where(r => r.HardwareId == item.HardwareId);
            strategy = "hardware_id";
        }
        else
        {
            return new SecurityBanSourceEvent
            {
                Found = false,
                Status = "source_not_searchable",
                SearchStrategy = strategy
            };
        }

        var windowStart = item.BannedAtUtc - NearSourceWindow;
        var windowEnd = item.BannedAtUtc + NearSourceWindow;
        var nearbyRecords = await query
            .Where(r => r.Timestamp >= windowStart && r.Timestamp <= windowEnd)
            .OrderByDescending(r => r.Timestamp)
            .Take(MaxTake)
            .ToListAsync(cancellationToken);
        var record = nearbyRecords
            .OrderBy(r => Math.Abs((r.Timestamp - item.BannedAtUtc).TotalSeconds))
            .FirstOrDefault();

        if (record == null)
        {
            var fallbackStart = item.BannedAtUtc - FallbackSourceWindow;
            var fallbackEnd = item.BannedAtUtc + FallbackSourceWindow;
            var fallbackRecords = await query
                .Where(r => r.Timestamp >= fallbackStart && r.Timestamp <= fallbackEnd)
                .OrderByDescending(r => r.Timestamp)
                .Take(MaxTake)
                .ToListAsync(cancellationToken);
            record = fallbackRecords
                .OrderBy(r => Math.Abs((r.Timestamp - item.BannedAtUtc).TotalSeconds))
                .FirstOrDefault();
        }

        if (record == null)
        {
            return new SecurityBanSourceEvent
            {
                Found = false,
                Status = "source_event_not_found",
                SearchStrategy = $"{strategy}_around_banned_at",
                CorrelationConfidence = "unavailable"
            };
        }

        var delta = Math.Abs((record.Timestamp - item.BannedAtUtc).TotalSeconds);
        var confidence = delta <= 5
            ? "exact"
            : delta <= NearSourceWindow.TotalSeconds
                ? "near_time_match"
                : "fallback_context";
        var properties = TelemetrySchemaRegistry.ParseProperties(record.EventData?.PropertiesJson);
        return new SecurityBanSourceEvent
        {
            Found = true,
            Status = confidence == "fallback_context" ? "fallback_context_found" : "source_event_found",
            SearchStrategy = $"{strategy}_around_banned_at",
            CorrelationConfidence = confidence,
            TimeDeltaSeconds = Math.Round(delta, 3),
            TelemetryRecordId = record.Id,
            TimestampUtc = record.Timestamp,
            HardwareId = record.HardwareId,
            EventName = record.EventName,
            Type = record.Type.ToString(),
            Version = record.Version,
            PropertyKeys = properties.Keys.OrderBy(k => k, StringComparer.OrdinalIgnoreCase).Take(50).ToList()
        };
    }

    private static void ApplySourceSummary(SecurityBanAuditItem item, SecurityBanSourceEvent source)
    {
        item.SourceEventAvailable = source.Found;
        item.SourceEventStatus = source.Status;
    }

    private static SecurityBanAuditItem MapHardwareBan(BannedHardwareId ban, string matchType)
    {
        return new SecurityBanAuditItem
        {
            BanId = ban.Id,
            TargetType = "hardware_id",
            IsActive = ban.IsActive,
            ProductId = ban.ProductId,
            ProductName = ban.Product?.Name,
            BannedAtUtc = ban.BannedAt,
            ExpiresAtUtc = ban.ExpiresAt,
            HardwareId = ban.HardwareId,
            BanCategory = ban.BanCategory ?? BannedHardwareId.Categories.Manual,
            Reason = ban.Reason,
            MatchType = matchType
        };
    }

    private static SecurityBanAuditItem MapComponentBan(BannedComponent ban, string matchType)
    {
        return new SecurityBanAuditItem
        {
            BanId = ban.Id,
            TargetType = "component",
            IsActive = ban.IsActive,
            ProductId = ban.ProductId,
            ProductName = ban.Product?.Name,
            BannedAtUtc = ban.BannedAt,
            ExpiresAtUtc = ban.ExpiresAt,
            ComponentType = ban.ComponentType,
            ComponentHash = ban.ComponentHash,
            ComponentHashRedacted = RedactHash(ban.ComponentHash),
            ComponentMatchType = ban.ComponentType,
            ComponentMatchStrength = GetComponentMatchStrength(ban.ComponentType),
            ComponentMatchSummary = GetComponentMatchSummary(ban.ComponentType),
            IsWeakComponentCorrelation = IsWeakComponentCorrelation(ban.ComponentType),
            Reason = ban.Reason,
            MatchType = matchType
        };
    }

    private static string GetComponentMatchStrength(string? componentType)
    {
        return NormalizeComponentType(componentType) switch
        {
            "FP_EXE" or "FP_DLL" or "FP_CORE" => "strong",
            "DISK" or "BIOS" or "CPU" or "HOST" => "medium",
            "MB" => "weak",
            _ => "unknown"
        };
    }

    private static string GetComponentMatchSummary(string? componentType)
    {
        return NormalizeComponentType(componentType) switch
        {
            "FP_EXE" => "Binary executable fingerprint match",
            "FP_DLL" => "Binary library fingerprint match",
            "FP_CORE" => "Binary core fingerprint match",
            "DISK" => "Disk fingerprint match",
            "BIOS" => "BIOS fingerprint match",
            "CPU" => "CPU fingerprint match",
            "HOST" => "Host fingerprint match",
            "MB" => "Motherboard fingerprint only; weak correlation, especially on virtual machines",
            _ => "Component fingerprint match"
        };
    }

    private static bool IsWeakComponentCorrelation(string? componentType) =>
        string.Equals(NormalizeComponentType(componentType), "MB", StringComparison.OrdinalIgnoreCase);

    private static SearchCriteria NormalizeCriteria(
        string? hardwareId,
        string? componentHash,
        string? componentType,
        string? clientIp,
        string? emailFragment,
        string? licenseFragment)
    {
        return new SearchCriteria(
            NormalizeOptional(hardwareId)?.ToUpperInvariant(),
            NormalizeOptional(componentHash)?.ToUpperInvariant(),
            NormalizeComponentType(componentType),
            NormalizeOptional(clientIp),
            NormalizeOptional(emailFragment)?.ToLowerInvariant(),
            CompactKey(licenseFragment));
    }

    private static string? NormalizeComponentType(string? value)
    {
        var normalized = NormalizeOptional(value)?.ToUpperInvariant();
        return normalized switch
        {
            "FP_CPU" => "CPU",
            "FP_MB" => "MB",
            "FP_BIOS" => "BIOS",
            "FP_DISK" => "DISK",
            "FP_HOST" => "HOST",
            _ => normalized
        };
    }

    private static bool HasOnlyComponentCriteria(SearchCriteria criteria) =>
        criteria.ComponentHash != null || criteria.ComponentType != null;

    private static void AddHash(HashSet<string> hashes, string? value)
    {
        if (!string.IsNullOrWhiteSpace(value))
            hashes.Add(value);
    }

    private static string? NormalizeOptional(string? value)
    {
        var trimmed = value?.Trim();
        return string.IsNullOrWhiteSpace(trimmed) ? null : trimmed;
    }

    private static string? CompactKey(string? value)
    {
        var normalized = NormalizeOptional(value);
        return normalized == null
            ? null
            : normalized.Replace("-", "", StringComparison.Ordinal).Replace(" ", "", StringComparison.Ordinal).ToUpperInvariant();
    }

    private static string? RedactHash(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return null;
        return value.Length <= 16 ? value : $"{value[..8]}...{value[^8..]}";
    }

    private sealed record SearchCriteria(
        string? HardwareId,
        string? ComponentHash,
        string? ComponentType,
        string? ClientIp,
        string? EmailFragment,
        string? LicenseFragment);
}
