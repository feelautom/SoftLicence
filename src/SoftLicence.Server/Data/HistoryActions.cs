namespace SoftLicence.Server.Data;

public static class HistoryActions
{
    public const string Created = "CREATED";
    public const string Activated = "ACTIVATED";
    public const string Recovery = "RECOVERY";
    public const string Revoked = "REVOKED";
    public const string Reactivated = "REACTIVATED";
    public const string UnlinkedApi = "UNLINKED_API";
    public const string UnlinkedManual = "UNLINKED_MANUAL";
    public const string UnlinkedAdminTool = "UNLINKED_ADMIN_TOOL";
    public const string GlobalReset = "GLOBAL_RESET";
    public const string Renewed = "RENEWED";
    public const string AutoUnlinkedProductScope = "Auto-Unlinked (Product Scope)";
    public const string HardwareIdV2Observed = "HWID_V2_OBSERVED";
    /// <summary>
    /// A cryptographically known Runtime enrollment selected an identifier that did not exist on
    /// the authenticated licence (TKT-001617). Audit only since TKT-003751: <see cref="Services.SeatChangeQuota"/>
    /// counts the activated identifier through <see cref="LicenseSeat.LastActivatedAt"/>, not history rows.
    /// </summary>
    public const string RuntimeCommercialNewIdentifier = "RUNTIME_COMMERCIAL_NEW_IDENTIFIER";
    /// <summary>
    /// A seat moved in place to a new hardware identifier by the signed Runtime migration (TKT-001277). Audit only
    /// since TKT-003751: the new identifier is counted through <see cref="LicenseSeat.LastActivatedAt"/>.
    /// </summary>
    public const string HardwareIdMigrated = "HWID_V2_MIGRATED";
    /// <summary>
    /// TKT-003350: an account relink took back the only seat of a single-seat licence from another machine, for a
    /// hardware identifier already known to that licence. Audit only since TKT-003751: the quota counts distinct
    /// identifiers activated per UTC day through <see cref="LicenseSeat.LastActivatedAt"/>.
    /// </summary>
    public const string RuntimeAccountRelinkSeatTakeover = "RUNTIME_ACCOUNT_RELINK_SEAT_TAKEOVER";
    /// <summary>A provider or administrator action disabled key-based activation for one license (TKT-002475).</summary>
    public const string KeyActivationDisabled = "KEY_ACTIVATION_DISABLED";
    /// <summary>A provider or administrator action lifted the key-activation refusal of one license (TKT-002475).</summary>
    public const string KeyActivationLifted = "KEY_ACTIVATION_LIFTED";
}
