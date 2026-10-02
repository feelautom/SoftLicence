using System.Collections.Frozen;

namespace SoftLicence.Server.Services.SecurityLocks;

/// <summary>
/// Server mirror of the Desktop closed cause catalogue (TKT-001177, DevBrain #1330 §1). Codes are canonical
/// upper-case ASCII compared ordinally; the level is fixed by the catalogue and a client claiming another
/// level is rejected. Must stay identical to SecurityLockCatalog in TiaPortalApi.
/// </summary>
public static class SecurityLockCauseCatalog
{
    /// <summary>Enforcement mode for reversible causes.</summary>
    public const string ModeNotApplicable = "NOT_APPLICABLE";
    /// <summary>Observed only; never blocks.</summary>
    public const string ModeShadow = "SHADOW";
    /// <summary>Reversible block plus admin review.</summary>
    public const string ModeReview = "REVIEW";
    /// <summary>Irreversible: permanent lockdown and automatic hardware ban.</summary>
    public const string ModeEnforce = "ENFORCE";

    private static readonly FrozenDictionary<string, int> Levels = new Dictionary<string, int>(StringComparer.Ordinal)
    {
        ["RE_TOOL_PRESENT"] = 0,
        ["RE_TOOL_UNKNOWN_PUBLISHER"] = 0,
        ["API_AUTH_FAILURES_BURST"] = 0,
        ["HEARTBEAT_UNREACHABLE"] = 1,
        ["LICENSE_EXPIRED"] = 2,
        ["LICENSE_INACTIVE"] = 2,
        ["LICENSE_SUSPENDED"] = 2,
        ["LICENSE_DISABLED"] = 2,
        ["SERVER_REVOKED"] = 3,
        ["SERVER_BANNED"] = 3,
        ["SERVER_KILL_ORDER"] = 3,
        ["NATIVE_REVOCATION"] = 3,
        ["NATIVE_DLL_MISSING"] = 3,
        ["AUTHENTICODE_UNVERIFIABLE"] = 3,
        ["LEGACY_MARKER"] = 3,
        ["STATE_UNREADABLE"] = 3,
        ["OFFLINE_STATE_MISMATCH"] = 4,
        ["NATIVE_DLL_REPLACED"] = 4,
        ["BINARY_SIGNATURE_BAD_DIGEST"] = 4,
        ["RUNTIME_HASH_CHANGED"] = 4,
        ["DEBUGGER_ATTACHED_KERNEL"] = 5,
        ["RE_TOOL_HANDLE_CONFIRMED"] = 5
    }.ToFrozenDictionary(StringComparer.Ordinal);

    private static readonly FrozenSet<string> Modes = new[]
    {
        ModeNotApplicable, ModeShadow, ModeReview, ModeEnforce
    }.ToFrozenSet(StringComparer.Ordinal);

    /// <summary>All catalogued causes.</summary>
    public static IEnumerable<string> AllCauses => Levels.Keys;

    /// <summary>Resolves the fixed level of an exact catalogued cause.</summary>
    /// <param name="cause">Candidate code, compared ordinally without normalization.</param>
    /// <param name="level">Catalogued level.</param>
    public static bool TryGetLevel(string? cause, out int level)
    {
        level = 0;
        return cause != null && Levels.TryGetValue(cause, out level);
    }

    /// <summary>True for levels 4 and 5, whose enforced outcome is irreversible.</summary>
    /// <param name="level">Catalogued level.</param>
    public static bool IsIrreversibleCandidate(int level) => level is 4 or 5;

    /// <summary>True for an exact enforcement mode code.</summary>
    /// <param name="mode">Candidate mode.</param>
    public static bool IsMode(string? mode) => mode != null && Modes.Contains(mode);

    /// <summary>True for a mode an administrator may assign to an irreversible candidate cause.</summary>
    /// <param name="mode">Candidate mode.</param>
    public static bool IsPolicyMode(string? mode) =>
        string.Equals(mode, ModeShadow, StringComparison.Ordinal) ||
        string.Equals(mode, ModeReview, StringComparison.Ordinal) ||
        string.Equals(mode, ModeEnforce, StringComparison.Ordinal);
}
