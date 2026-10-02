namespace SoftLicence.Server.Services.SecurityLocks;

/// <summary>Closed verdict codes returned to the Desktop.</summary>
public static class SecurityLockVerdicts
{
    /// <summary>Keep the lock.</summary>
    public const string Maintain = "MAINTAIN";
    /// <summary>Release the lock.</summary>
    public const string Release = "RELEASE";
    /// <summary>Permanent lockdown; the hardware identifier is banned server-side.</summary>
    public const string Ban = "BAN";
}

/// <summary>Closed report states persisted server-side.</summary>
public static class SecurityLockReportStates
{
    /// <summary>Waiting for an admin decision or a later automatic release.</summary>
    public const string Open = "OPEN";
    /// <summary>Released by rule or by an admin.</summary>
    public const string Released = "RELEASED";
    /// <summary>Hardware banned (automatic ENFORCE or admin decision).</summary>
    public const string Banned = "BANNED";
}

/// <summary>Closed admin decisions.</summary>
public static class SecurityLockAdminDecisions
{
    /// <summary>Admin releases the lock.</summary>
    public const string Release = "RELEASE";
    /// <summary>Admin bans the hardware.</summary>
    public const string Ban = "BAN";
}

/// <summary>Inputs of one verdict decision.</summary>
/// <param name="Cause">Catalogued cause.</param>
/// <param name="Level">Catalogued level.</param>
/// <param name="EffectiveMode">Server-side mode (policy table, default REVIEW) for levels 4 and 5.</param>
/// <param name="AdminDecision">Latest admin decision for this lock, if any.</param>
/// <param name="HardwareBanned">Whether an active ban already exists for this hardware and product.</param>
/// <param name="OpenCriticalIncident">Whether an unresolved critical canary incident exists for the binding.</param>
public sealed record SecurityLockDecisionInput(
    string Cause,
    int Level,
    string EffectiveMode,
    string? AdminDecision,
    bool HardwareBanned,
    bool OpenCriticalIncident);

/// <summary>Verdict and resulting persisted state.</summary>
/// <param name="Verdict">Closed verdict code.</param>
/// <param name="State">Closed report state.</param>
public sealed record SecurityLockDecision(string Verdict, string State);

/// <summary>
/// Pure verdict policy (TKT-001177, DevBrain #1329/#1330). Security contract: only the server releases a lock;
/// levels 1 and 2 are released because an authenticated report proves the server is reachable and the
/// enrollment authority (licence) was validated before this policy runs; level 3 needs an admin release except
/// a legacy marker on a clean record; levels 4 and 5 follow the server mode and are banned only in ENFORCE.
/// </summary>
public static class SecurityLockVerdictPolicy
{
    /// <summary>Default server mode for irreversible candidates: never ENFORCE by default.</summary>
    public const string DefaultIrreversibleMode = SecurityLockCauseCatalog.ModeReview;

    /// <summary>Applies the closed decision table.</summary>
    /// <param name="input">Decision inputs.</param>
    /// <returns>The verdict and resulting state.</returns>
    public static SecurityLockDecision Decide(SecurityLockDecisionInput input)
    {
        ArgumentNullException.ThrowIfNull(input);
        if (input.HardwareBanned || string.Equals(input.AdminDecision, SecurityLockAdminDecisions.Ban, StringComparison.Ordinal))
            return Banned();

        var irreversible = SecurityLockCauseCatalog.IsIrreversibleCandidate(input.Level);
        if (irreversible && string.Equals(input.EffectiveMode, SecurityLockCauseCatalog.ModeEnforce, StringComparison.Ordinal))
            return Banned();

        if (string.Equals(input.AdminDecision, SecurityLockAdminDecisions.Release, StringComparison.Ordinal))
            return Released();

        switch (input.Level)
        {
            case 0:
            case 1:
            case 2:
                return Released();
            case 3:
                return string.Equals(input.Cause, "LEGACY_MARKER", StringComparison.Ordinal) && !input.OpenCriticalIncident
                    ? Released()
                    : Open();
            default:
                return string.Equals(input.EffectiveMode, SecurityLockCauseCatalog.ModeShadow, StringComparison.Ordinal)
                    ? Released()
                    : Open();
        }
    }

    /// <summary>
    /// Resolves the server-side mode: reversible causes are NOT_APPLICABLE; irreversible ones use the configured
    /// policy or REVIEW when none exists. The client-claimed mode is informational only.
    /// </summary>
    /// <param name="level">Catalogued level.</param>
    /// <param name="configuredMode">Policy table mode, or null.</param>
    public static string ResolveEffectiveMode(int level, string? configuredMode)
    {
        if (!SecurityLockCauseCatalog.IsIrreversibleCandidate(level)) return SecurityLockCauseCatalog.ModeNotApplicable;
        return SecurityLockCauseCatalog.IsPolicyMode(configuredMode) ? configuredMode! : DefaultIrreversibleMode;
    }

    /// <summary>Ban category: debugger for level 5, piracy for level 4 (both permanent).</summary>
    /// <param name="level">Catalogued level.</param>
    public static string BanCategoryFor(int level) => level == 5 ? "debugger" : "piracy";

    private static SecurityLockDecision Released() => new(SecurityLockVerdicts.Release, SecurityLockReportStates.Released);
    private static SecurityLockDecision Open() => new(SecurityLockVerdicts.Maintain, SecurityLockReportStates.Open);
    private static SecurityLockDecision Banned() => new(SecurityLockVerdicts.Ban, SecurityLockReportStates.Banned);
}
