namespace SoftLicence.Server.Models;

/// <summary>
/// Read-only answer of <c>GET /api/analytics/licenses/paid-weekly-activity</c> (TKT-003652): one page of paid
/// (non-Freemium) licenses with ISO-week usage aggregates. It carries facts only (counts, dates, versions);
/// any retention or commercial interpretation belongs to the caller, never to SoftLicence.
/// </summary>
public sealed class PaidWeeklyActivityResponse
{
    /// <summary>UTC time the aggregates were computed.</summary>
    public DateTime GeneratedAtUtc { get; set; } = DateTime.UtcNow;

    /// <summary>True when this exact request was served from the 60-second in-process cache.</summary>
    public bool Cached { get; set; }

    /// <summary>UTC time after which a cached copy is recomputed.</summary>
    public DateTime ExpiresAtUtc { get; set; }

    /// <summary>Number of ISO weeks covered, current partial week included (1 to 52).</summary>
    public int Weeks { get; set; }

    /// <summary>Inclusive UTC start of the window: Monday 00:00 of the oldest covered ISO week.</summary>
    public DateTime FromUtc { get; set; }

    /// <summary>Exclusive UTC end of the window (computation time).</summary>
    public DateTime ToUtc { get; set; }

    /// <summary>Normalized status filter actually applied.</summary>
    public string StatusFilter { get; set; } = "active";

    /// <summary>Requested type filters, empty when every paid type is included.</summary>
    public List<string> LicenseTypes { get; set; } = new();

    /// <summary>Paid licenses matching the filters before pagination.</summary>
    public int TotalLicenses { get; set; }

    /// <summary>Number of licenses skipped before this page.</summary>
    public int Skip { get; set; }

    /// <summary>Maximum page size applied (1 to 200).</summary>
    public int Take { get; set; }

    /// <summary>Licenses of this page, ordered by creation date then license ID.</summary>
    public List<PaidWeeklyActivityLicense> Licenses { get; set; } = new();
}

/// <summary>One paid license with its seats and its non-empty weekly aggregates.</summary>
public sealed class PaidWeeklyActivityLicense
{
    /// <summary>License identifier, stable across calls.</summary>
    public Guid LicenseId { get; set; }

    /// <summary>License type slug.</summary>
    public string LicenseTypeSlug { get; set; } = "";

    /// <summary>License type display name.</summary>
    public string LicenseTypeName { get; set; } = "";

    /// <summary>Key status at computation time: active, expired or revoked.</summary>
    public string LicenseStatus { get; set; } = "";

    /// <summary>Key creation date (UTC).</summary>
    public DateTime CreatedAtUtc { get; set; }

    /// <summary>First activation date of the key (UTC), when known.</summary>
    public DateTime? ActivationDateUtc { get; set; }

    /// <summary>Key expiration date (UTC); null for a lifetime key. This is the key period, not a commercial period.</summary>
    public DateTime? ExpirationDateUtc { get; set; }

    /// <summary>Customer e-mail in full, as in the other authenticated analytics answers.</summary>
    public string CustomerEmail { get; set; } = "";

    /// <summary>License key masked to its first and last four characters.</summary>
    public string LicenseKeyRedacted { get; set; } = "";

    /// <summary>Last telemetry event of any kind attributed to this license inside the window.</summary>
    public DateTime? LastSeenUtc { get; set; }

    /// <summary>Last real usage event (see <see cref="PaidWeeklyActivityWeek.UsageEvents"/>) inside the window.</summary>
    public DateTime? LastUsageUtc { get; set; }

    /// <summary>Every seat ever recorded for the license, active or released, with masked hardware IDs.</summary>
    public List<PaidWeeklyActivitySeat> Seats { get; set; } = new();

    /// <summary>Weeks with at least one attributed event or new seat, oldest first; empty weeks are omitted.</summary>
    public List<PaidWeeklyActivityWeek> WeeklyActivity { get; set; } = new();
}

/// <summary>One machine seat of a paid license.</summary>
public sealed class PaidWeeklyActivitySeat
{
    /// <summary>16-hex-character SHA-256 prefix of the upper-cased hardware ID, for correlation without disclosure.</summary>
    public string HardwareIdHash { get; set; } = "";

    /// <summary>Hardware ID masked to its first six and last four characters.</summary>
    public string HardwareIdRedacted { get; set; } = "";

    /// <summary>First activation of this machine on the license (UTC).</summary>
    public DateTime FirstActivatedAtUtc { get; set; }

    /// <summary>Release date of the seat (UTC), null while linked.</summary>
    public DateTime? UnlinkedAtUtc { get; set; }

    /// <summary>True while the seat is linked.</summary>
    public bool IsActive { get; set; }
}

/// <summary>Usage aggregates of one license for one ISO week (Monday to Sunday, UTC).</summary>
public sealed class PaidWeeklyActivityWeek
{
    /// <summary>ISO week label, for example 2026-W46.</summary>
    public string IsoWeek { get; set; } = "";

    /// <summary>Monday 00:00 UTC of the week.</summary>
    public DateTime WeekStartUtc { get; set; }

    /// <summary>Distinct UTC days with any attributed telemetry event.</summary>
    public int ActiveDays { get; set; }

    /// <summary>Distinct UTC days with at least one real usage event.</summary>
    public int UsageDays { get; set; }

    /// <summary>Application starts (<c>Startup_AppStarted</c> events).</summary>
    public int Startups { get; set; }

    /// <summary>
    /// Real usage events: event telemetry other than startup, license, update, UI, wizard, telemetry,
    /// certificate-pinning, MCP connection and MCP result plumbing, and API authentication failures.
    /// </summary>
    public int UsageEvents { get; set; }

    /// <summary>Distinct usage event names (case-insensitive).</summary>
    public int DistinctUsageEvents { get; set; }

    /// <summary>MCP tool calls (<c>Mcp_ToolCall</c>).</summary>
    public int McpToolCalls { get; set; }

    /// <summary>Copilot tool calls (<c>Copilot_ToolCall</c>).</summary>
    public int CopilotToolCalls { get; set; }

    /// <summary>Telemetry records of type Error.</summary>
    public int Errors { get; set; }

    /// <summary>License failures: license or no-license events naming a failure, invalid key, mismatch, missing, refusal, expiry or revocation.</summary>
    public int LicenseFailures { get; set; }

    /// <summary>License prompts shown to the user (<c>LicensePrompt_Shown</c>), i.e. starts without a usable license.</summary>
    public int LicensePrompts { get; set; }

    /// <summary>Distinct machines with attributed telemetry this week.</summary>
    public int Machines { get; set; }

    /// <summary>Seats of the license first activated during this week.</summary>
    public int NewMachines { get; set; }

    /// <summary>Highest application version seen this week, null when no event carried a version.</summary>
    public string? LatestVersion { get; set; }
}
