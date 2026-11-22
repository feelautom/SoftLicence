using System.Globalization;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;

namespace SoftLicence.Server.Services;

/// <summary>
/// Builds compact ISO-week usage aggregates for paid (non-Freemium) licenses over up to 52 weeks (TKT-003652).
/// It exists because the per-machine ranking stops at 30 days and the license timeline returns raw events:
/// a weekly retention report needs a year of history at a few lines per customer.
/// </summary>
/// <remarks>
/// <para>
/// Read-only. The heavy reduction runs in PostgreSQL: telemetry rows are grouped by upper-cased hardware ID,
/// UTC day, event name, type and version, using the existing (ProductId, Timestamp) index for the window.
/// Only those grouped rows (a few thousand per page) reach memory; no raw event is ever returned.
/// </para>
/// <para>
/// Machine attribution: telemetry carries a hardware ID, not a license. Every seat of every license of the
/// product (paid or not, active or released, plus the legacy <see cref="License.HardwareId"/> of licenses
/// without seat history) is a claim starting at its activation date. A telemetry day belongs to the latest
/// claim of that machine that started on or before the day; days up to 7 days before the first claim belong
/// to that first claim, because a customer often starts and fails to activate before the seat exists. A
/// released seat keeps its later days until another license claims the machine, so license failures after a
/// release still show on the departing customer. Attribution is decided per UTC day.
/// </para>
/// <para>
/// String contract: hardware IDs are machine identifiers compared after upper-casing (invariant in .NET,
/// <c>upper()</c> in PostgreSQL; identical for the ASCII alphabet hardware IDs use). Event names are compared
/// ordinal and case-insensitively. No commercial rule is applied: SoftLicence reports usage facts only.
/// </para>
/// </remarks>
public sealed class PaidWeeklyActivityAnalyticsService
{
    private const int DefaultWeeks = 12;
    private const int MaxWeeks = 52;
    private const int DefaultTake = 100;
    private const int MaxTake = 200;
    private const int PreActivationGraceDays = 7;
    private static readonly TimeSpan CacheTtl = TimeSpan.FromSeconds(60);

    private static readonly string[] NonUsagePrefixes =
    {
        "Startup_", "License", "Update_", "UI_", "Wizard_", "Telemetry", "CertPinning",
        "Mcp_ClientConnected", "Mcp_ToolResult", "API_AuthFailed"
    };

    private static readonly string[] LicenseFailureMarkers =
    {
        "Fail", "Invalid", "Mismatch", "NoLicense", "Missing", "Refused", "Rejected", "Denied", "Expired", "Revoked"
    };

    private readonly IDbContextFactory<LicenseDbContext> _dbFactory;
    private readonly IMemoryCache _cache;

    /// <summary>Creates the service over the shared context factory and the process memory cache.</summary>
    public PaidWeeklyActivityAnalyticsService(IDbContextFactory<LicenseDbContext> dbFactory, IMemoryCache cache)
    {
        _dbFactory = dbFactory;
        _cache = cache;
    }

    /// <summary>
    /// Returns one page of paid licenses of the product scope with their seats and non-empty weekly aggregates.
    /// </summary>
    /// <param name="productId">Root product already authorized by the caller; its product scope is included.</param>
    /// <param name="licenseTypes">Comma-separated paid type slugs or names (case-insensitive); empty means all paid types.</param>
    /// <param name="status">active, expired, revoked, expired_or_revoked or all; unknown values mean active.</param>
    /// <param name="weeks">ISO weeks to cover including the current one, clamped to 1-52 (default 12).</param>
    /// <param name="skip">Licenses to skip, clamped to 0 or more.</param>
    /// <param name="take">Page size, clamped to 1-200 (default 100).</param>
    /// <param name="cancellationToken">Cancels the database reads.</param>
    /// <returns>The page; identical requests within 60 seconds are served from cache with <c>Cached</c> set.</returns>
    public async Task<PaidWeeklyActivityResponse> GetForProductIdAsync(
        Guid productId,
        string? licenseTypes = null,
        string? status = "active",
        int weeks = DefaultWeeks,
        int skip = 0,
        int take = DefaultTake,
        CancellationToken cancellationToken = default)
    {
        var normalizedTypes = FreemiumActivityRankingAnalyticsService.NormalizeLicenseTypes(licenseTypes);
        var statusFilter = FreemiumActivityRankingAnalyticsService.NormalizeStatus(status);
        weeks = Math.Clamp(weeks, 1, MaxWeeks);
        skip = Math.Max(0, skip);
        take = Math.Clamp(take, 1, MaxTake);

        var cacheKey = string.Join(':',
            "paid-weekly-activity",
            productId.ToString("N"),
            normalizedTypes.Count == 0
                ? "ALL_PAID"
                : string.Join(',', normalizedTypes.Select(t => t.ToUpperInvariant()).OrderBy(t => t, StringComparer.Ordinal)),
            statusFilter,
            weeks,
            skip,
            take);
        if (_cache.TryGetValue(cacheKey, out PaidWeeklyActivityResponse? cached) && cached != null)
        {
            cached.Cached = true;
            return cached;
        }

        var now = DateTime.UtcNow;
        var fromUtc = StartOfIsoWeek(now).AddDays(-7 * (weeks - 1));

        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        var productScopeIds = await ProductScopeResolver.ResolveProductScopeIdsAsync(db, productId, cancellationToken);

        // Type filtering stays in memory: the paid rule reads slug and name markers case-insensitively,
        // which a SQL LIKE would evaluate with collation-dependent casing. The license table is small.
        var licenses = (await db.Licenses.AsNoTracking()
                .Include(l => l.Type)
                .Include(l => l.Seats)
                .Where(l => productScopeIds.Contains(l.ProductId) && l.Type != null)
                .ToListAsync(cancellationToken))
            .Where(l => FreemiumActivityRankingAnalyticsService.IsPaidType(l.Type!))
            .Where(l => normalizedTypes.Count == 0
                || normalizedTypes.Contains(l.Type!.Slug, StringComparer.OrdinalIgnoreCase)
                || normalizedTypes.Contains(l.Type!.Name, StringComparer.OrdinalIgnoreCase))
            .Where(l => FreemiumActivityRankingAnalyticsService.StatusMatches(
                statusFilter,
                FreemiumActivityRankingAnalyticsService.ResolveLicenseStatus(l, now)))
            .OrderBy(l => l.CreationDate)
            .ThenBy(l => l.Id)
            .ToList();

        var page = licenses.Skip(skip).Take(take).ToList();
        var pageHardwareIds = page
            .SelectMany(MachineClaimsOf)
            .Select(claim => claim.HardwareId)
            .Distinct(StringComparer.Ordinal)
            .ToList();

        var claimsByMachine = await LoadMachineClaimsAsync(db, productScopeIds, pageHardwareIds, cancellationToken);
        var rows = await LoadDailyRowsAsync(db, productScopeIds, pageHardwareIds, fromUtc, now, cancellationToken);

        var buckets = new Dictionary<Guid, LicenseAccumulator>();
        foreach (var row in rows)
        {
            if (!claimsByMachine.TryGetValue(row.HardwareId, out var claims))
                continue;
            var owner = ResolveOwner(claims, row.DayUtc);
            if (owner == null)
                continue;
            if (!buckets.TryGetValue(owner.Value, out var accumulator))
                buckets[owner.Value] = accumulator = new LicenseAccumulator();
            accumulator.Add(row);
        }

        var response = new PaidWeeklyActivityResponse
        {
            GeneratedAtUtc = now,
            Cached = false,
            ExpiresAtUtc = now.Add(CacheTtl),
            Weeks = weeks,
            FromUtc = fromUtc,
            ToUtc = now,
            StatusFilter = statusFilter,
            LicenseTypes = normalizedTypes,
            TotalLicenses = licenses.Count,
            Skip = skip,
            Take = take,
            Licenses = page
                .Select(license => BuildLicense(license, buckets.GetValueOrDefault(license.Id), fromUtc, now))
                .ToList()
        };

        _cache.Set(cacheKey, response, CacheTtl);
        return response;
    }

    /// <summary>
    /// Loads every claim on the given machines across the whole product scope, including free and other
    /// customers' licenses, so a machine that changed hands is attributed to the right license per day.
    /// </summary>
    /// <returns>Claims per upper-cased hardware ID, ordered by start then license ID for deterministic ties.</returns>
    private static async Task<Dictionary<string, List<MachineClaim>>> LoadMachineClaimsAsync(
        LicenseDbContext db,
        List<Guid> productScopeIds,
        List<string> hardwareIds,
        CancellationToken cancellationToken)
    {
        if (hardwareIds.Count == 0)
            return new Dictionary<string, List<MachineClaim>>(StringComparer.Ordinal);

        // upper() on the column is deliberate: stored seat IDs may predate canonical casing. LicenseSeats is
        // small and the product predicate bounds the scan, so the lost HardwareId index lookup is acceptable.
        var seatClaims = await db.LicenseSeats.AsNoTracking()
            .Where(s => productScopeIds.Contains(s.License!.ProductId) && hardwareIds.Contains(s.HardwareId.ToUpper()))
            .Select(s => new { s.LicenseId, s.HardwareId, s.FirstActivatedAt })
            .ToListAsync(cancellationToken);

        // Legacy licenses without any seat row still own their single historical machine.
        var legacyClaims = await db.Licenses.AsNoTracking()
            .Where(l => productScopeIds.Contains(l.ProductId)
                && !l.Seats.Any()
                && l.HardwareId != null
                && hardwareIds.Contains(l.HardwareId.ToUpper()))
            .Select(l => new { LicenseId = l.Id, HardwareId = l.HardwareId!, Start = l.ActivationDate ?? l.CreationDate })
            .ToListAsync(cancellationToken);

        return seatClaims
            .Select(s => new MachineClaim(s.LicenseId, s.HardwareId.ToUpperInvariant(), s.FirstActivatedAt))
            .Concat(legacyClaims.Select(l => new MachineClaim(l.LicenseId, l.HardwareId.ToUpperInvariant(), l.Start)))
            .GroupBy(c => c.HardwareId, StringComparer.Ordinal)
            .ToDictionary(
                g => g.Key,
                g => g.OrderBy(c => c.StartUtc).ThenBy(c => c.LicenseId).ToList(),
                StringComparer.Ordinal);
    }

    /// <summary>
    /// Reads the window's telemetry for the given machines, reduced in SQL to one row per machine, UTC day,
    /// event name, type and version with its count and latest timestamp.
    /// </summary>
    private static async Task<List<DailyRow>> LoadDailyRowsAsync(
        LicenseDbContext db,
        List<Guid> productScopeIds,
        List<string> hardwareIds,
        DateTime fromUtc,
        DateTime toUtc,
        CancellationToken cancellationToken)
    {
        if (hardwareIds.Count == 0)
            return new List<DailyRow>();

        // The (ProductId, Timestamp) index bounds the scan to the window; there is no telemetry HardwareId
        // index, so upper() on the column costs nothing extra and tolerates historical lower-case IDs.
        var grouped = await db.TelemetryRecords.AsNoTracking()
            .Where(r => r.ProductId.HasValue && productScopeIds.Contains(r.ProductId.Value)
                && r.Timestamp >= fromUtc && r.Timestamp < toUtc
                && hardwareIds.Contains(r.HardwareId.ToUpper()))
            .GroupBy(r => new { HardwareId = r.HardwareId.ToUpper(), Day = r.Timestamp.Date, r.EventName, r.Type, r.Version })
            .Select(g => new
            {
                g.Key.HardwareId,
                g.Key.Day,
                g.Key.EventName,
                g.Key.Type,
                g.Key.Version,
                Count = g.Count(),
                LastUtc = g.Max(r => r.Timestamp)
            })
            .ToListAsync(cancellationToken);

        return grouped
            .Select(g => new DailyRow(
                g.HardwareId,
                DateTime.SpecifyKind(g.Day, DateTimeKind.Utc),
                g.EventName,
                g.Type,
                g.Version,
                g.Count,
                DateTime.SpecifyKind(g.LastUtc, DateTimeKind.Utc)))
            .ToList();
    }

    /// <summary>
    /// Picks the license owning a machine on a UTC day: the latest claim started on or before that day, or the
    /// first claim when the day falls within the pre-activation grace period. Null means nobody owned it yet.
    /// </summary>
    private static Guid? ResolveOwner(List<MachineClaim> claims, DateTime dayUtc)
    {
        MachineClaim? owner = null;
        foreach (var claim in claims)
        {
            if (claim.StartUtc.Date <= dayUtc)
                owner = claim;
        }

        if (owner != null)
            return owner.LicenseId;

        var first = claims[0];
        return first.StartUtc.Date.AddDays(-PreActivationGraceDays) <= dayUtc ? first.LicenseId : null;
    }

    /// <summary>
    /// Lists the machines a license has ever used: all seat rows, or its legacy hardware ID when it has no
    /// seat history. IDs are upper-cased; the start is the seat activation (or license activation/creation).
    /// </summary>
    private static IEnumerable<MachineClaim> MachineClaimsOf(License license)
    {
        if (license.Seats.Count > 0)
        {
            return license.Seats
                .Where(s => !string.IsNullOrWhiteSpace(s.HardwareId))
                .Select(s => new MachineClaim(license.Id, s.HardwareId.ToUpperInvariant(), s.FirstActivatedAt));
        }

        return string.IsNullOrWhiteSpace(license.HardwareId)
            ? Enumerable.Empty<MachineClaim>()
            : new[] { new MachineClaim(license.Id, license.HardwareId.ToUpperInvariant(), license.ActivationDate ?? license.CreationDate) };
    }

    /// <summary>
    /// Projects one license with its masked seats and its weekly aggregates. Weeks with neither an attributed
    /// event nor a new seat are omitted to keep a year of history compact; callers fill the gaps as zero.
    /// </summary>
    private static PaidWeeklyActivityLicense BuildLicense(
        License license,
        LicenseAccumulator? accumulator,
        DateTime fromUtc,
        DateTime now)
    {
        var newSeatsByWeek = license.Seats
            .Where(s => s.FirstActivatedAt >= fromUtc && s.FirstActivatedAt < now)
            .GroupBy(s => StartOfIsoWeek(s.FirstActivatedAt))
            .ToDictionary(g => g.Key, g => g.Count());

        var weekStarts = (accumulator?.Weeks.Keys ?? Enumerable.Empty<DateTime>())
            .Concat(newSeatsByWeek.Keys)
            .Distinct()
            .OrderBy(w => w);

        return new PaidWeeklyActivityLicense
        {
            LicenseId = license.Id,
            LicenseTypeSlug = license.Type?.Slug ?? "",
            LicenseTypeName = license.Type?.Name ?? "",
            LicenseStatus = FreemiumActivityRankingAnalyticsService.ResolveLicenseStatus(license, now),
            CreatedAtUtc = license.CreationDate,
            ActivationDateUtc = license.ActivationDate,
            ExpirationDateUtc = license.ExpirationDate,
            CustomerEmail = license.CustomerEmail,
            LicenseKeyRedacted = FreemiumActivityRankingAnalyticsService.RedactKey(license.LicenseKey),
            LastSeenUtc = accumulator?.LastSeenUtc,
            LastUsageUtc = accumulator?.LastUsageUtc,
            Seats = license.Seats
                .OrderBy(s => s.FirstActivatedAt)
                .Select(s => new PaidWeeklyActivitySeat
                {
                    HardwareIdHash = FreemiumActivityRankingAnalyticsService.HashHardwareId(s.HardwareId.ToUpperInvariant()),
                    HardwareIdRedacted = FreemiumActivityRankingAnalyticsService.RedactHardwareId(s.HardwareId),
                    FirstActivatedAtUtc = s.FirstActivatedAt,
                    UnlinkedAtUtc = s.UnlinkedAt,
                    IsActive = s.IsActive
                })
                .ToList(),
            WeeklyActivity = weekStarts
                .Select(weekStart =>
                {
                    var week = accumulator?.Weeks.GetValueOrDefault(weekStart)?.ToWeek(weekStart) ?? EmptyWeek(weekStart);
                    week.NewMachines = newSeatsByWeek.GetValueOrDefault(weekStart);
                    return week;
                })
                .ToList()
        };
    }

    /// <summary>Creates a zero week used when only a new seat, and no telemetry, marks the week.</summary>
    private static PaidWeeklyActivityWeek EmptyWeek(DateTime weekStart) => new()
    {
        IsoWeek = FormatIsoWeek(weekStart),
        WeekStartUtc = weekStart
    };

    /// <summary>Returns Monday 00:00 UTC of the ISO week containing <paramref name="utc"/>.</summary>
    internal static DateTime StartOfIsoWeek(DateTime utc)
    {
        var day = DateTime.SpecifyKind(utc.Date, DateTimeKind.Utc);
        var offset = ((int)day.DayOfWeek + 6) % 7;
        return day.AddDays(-offset);
    }

    /// <summary>Formats an ISO week label such as 2026-W46 (ISO year, which can differ from the calendar year).</summary>
    internal static string FormatIsoWeek(DateTime weekStart) =>
        string.Create(CultureInfo.InvariantCulture, $"{ISOWeek.GetYear(weekStart)}-W{ISOWeek.GetWeekOfYear(weekStart):00}");

    /// <summary>
    /// True for events that represent real work in the product, false for startup, license, update, UI,
    /// wizard, telemetry, certificate-pinning, MCP plumbing and API authentication failures, and for errors.
    /// </summary>
    internal static bool IsUsageEvent(string? eventName, TelemetryType type) =>
        type == TelemetryType.Event
        && !string.IsNullOrWhiteSpace(eventName)
        && !NonUsagePrefixes.Any(prefix => eventName.StartsWith(prefix, StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// True for license-related events naming a failure (license, license-cache, license-activation, and
    /// startup no-license events containing a failure, invalid, mismatch, missing, refusal, expiry or revocation
    /// marker). Prompt-shown events are counted separately and are not failures by themselves.
    /// </summary>
    internal static bool IsLicenseFailure(string? eventName)
    {
        if (string.IsNullOrWhiteSpace(eventName))
            return false;
        var licenseRelated = eventName.StartsWith("License", StringComparison.OrdinalIgnoreCase)
            || eventName.StartsWith("Startup_NoLicense", StringComparison.OrdinalIgnoreCase);
        return licenseRelated
            && LicenseFailureMarkers.Any(marker => eventName.Contains(marker, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>One machine ownership claim: a license started using a machine at a given time.</summary>
    private sealed record MachineClaim(Guid LicenseId, string HardwareId, DateTime StartUtc);

    /// <summary>One SQL-grouped telemetry row: a machine, UTC day, event, type and version with its count.</summary>
    private sealed record DailyRow(
        string HardwareId,
        DateTime DayUtc,
        string? EventName,
        TelemetryType Type,
        string? Version,
        int Count,
        DateTime LastUtc);

    /// <summary>Accumulates the attributed rows of one license, per ISO week.</summary>
    private sealed class LicenseAccumulator
    {
        /// <summary>Week accumulators keyed by Monday 00:00 UTC.</summary>
        public Dictionary<DateTime, WeekAccumulator> Weeks { get; } = new();

        /// <summary>Latest attributed event of any kind.</summary>
        public DateTime? LastSeenUtc { get; private set; }

        /// <summary>Latest attributed usage event.</summary>
        public DateTime? LastUsageUtc { get; private set; }

        /// <summary>Adds one grouped row to its week and updates the last-seen markers.</summary>
        public void Add(DailyRow row)
        {
            var weekStart = StartOfIsoWeek(row.DayUtc);
            if (!Weeks.TryGetValue(weekStart, out var week))
                Weeks[weekStart] = week = new WeekAccumulator();
            var usage = week.Add(row);

            if (LastSeenUtc == null || row.LastUtc > LastSeenUtc)
                LastSeenUtc = row.LastUtc;
            if (usage && (LastUsageUtc == null || row.LastUtc > LastUsageUtc))
                LastUsageUtc = row.LastUtc;
        }
    }

    /// <summary>Accumulates one license-week; see <see cref="PaidWeeklyActivityWeek"/> for each counter's meaning.</summary>
    private sealed class WeekAccumulator
    {
        private readonly HashSet<DateTime> _days = new();
        private readonly HashSet<DateTime> _usageDays = new();
        private readonly HashSet<string> _usageEventNames = new(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> _machines = new(StringComparer.Ordinal);
        private Version? _latestVersion;
        private string? _latestVersionText;
        private int _startups, _usageEvents, _mcpToolCalls, _copilotToolCalls, _errors, _licenseFailures, _licensePrompts;

        /// <summary>Adds one grouped row and returns whether it counted as usage.</summary>
        public bool Add(DailyRow row)
        {
            _days.Add(row.DayUtc);
            _machines.Add(row.HardwareId);
            var name = row.EventName ?? "";

            if (string.Equals(name, "Startup_AppStarted", StringComparison.OrdinalIgnoreCase))
                _startups += row.Count;
            if (string.Equals(name, "Mcp_ToolCall", StringComparison.OrdinalIgnoreCase))
                _mcpToolCalls += row.Count;
            if (string.Equals(name, "Copilot_ToolCall", StringComparison.OrdinalIgnoreCase))
                _copilotToolCalls += row.Count;
            if (string.Equals(name, "LicensePrompt_Shown", StringComparison.OrdinalIgnoreCase))
                _licensePrompts += row.Count;
            if (row.Type == TelemetryType.Error)
                _errors += row.Count;
            if (IsLicenseFailure(name))
                _licenseFailures += row.Count;

            // Versions compare numerically (2.10 > 2.9); unparsable strings only win when nothing parsed.
            if (!string.IsNullOrWhiteSpace(row.Version))
            {
                if (Version.TryParse(row.Version.Trim(), out var parsed))
                {
                    if (_latestVersion == null || parsed > _latestVersion)
                    {
                        _latestVersion = parsed;
                        _latestVersionText = row.Version.Trim();
                    }
                }
                else if (_latestVersion == null)
                {
                    _latestVersionText ??= row.Version.Trim();
                }
            }

            if (!IsUsageEvent(name, row.Type))
                return false;

            _usageEvents += row.Count;
            _usageDays.Add(row.DayUtc);
            _usageEventNames.Add(name);
            return true;
        }

        /// <summary>Freezes the counters into the public week shape (new machines are set by the caller).</summary>
        public PaidWeeklyActivityWeek ToWeek(DateTime weekStart) => new()
        {
            IsoWeek = FormatIsoWeek(weekStart),
            WeekStartUtc = weekStart,
            ActiveDays = _days.Count,
            UsageDays = _usageDays.Count,
            Startups = _startups,
            UsageEvents = _usageEvents,
            DistinctUsageEvents = _usageEventNames.Count,
            McpToolCalls = _mcpToolCalls,
            CopilotToolCalls = _copilotToolCalls,
            Errors = _errors,
            LicenseFailures = _licenseFailures,
            LicensePrompts = _licensePrompts,
            Machines = _machines.Count,
            LatestVersion = _latestVersionText
        };
    }
}
