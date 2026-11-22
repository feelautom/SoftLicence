namespace SoftLicence.Server.Services;

/// <summary>
/// The endpoint labels passed to <see cref="MachineIdentityObservationService"/> and stored in
/// <see cref="Data.MachineEvidenceObservation.LastEndpoint"/> (TKT-004112).
/// </summary>
/// <remarks>
/// <para>
/// Each label is an upper-case ASCII code stored exactly as written: it is never compared, indexed or normalized,
/// and it is only read by support and analytics to know which route last saw a machine. The status labels
/// (<see cref="Check"/>, <see cref="CloneGuardReactivate"/>) are also the audit tags of those routes, so renaming
/// one changes what support reads in the access logs.
/// </para>
/// <para>
/// Every label must fit <see cref="Data.MachineEvidenceObservation.MaxEndpointLength"/>: storage is fail-open, so
/// a longer label would not break the request but would silently lose the evidence (the TKT-004112 defect).
/// A test enumerates these constants and enforces the limit; add any new label here.
/// </para>
/// </remarks>
public static class MachineEvidenceEndpoints
{
    /// <summary>Licence activation (<c>POST /api/activation</c>).</summary>
    public const string Activate = "ACTIVATE";

    /// <summary>Licence status check (<c>POST /api/activation/check</c>).</summary>
    public const string Check = "CHECK";

    /// <summary>Automatic trial request.</summary>
    public const string Trial = "TRIAL";

    /// <summary>Runtime distribution preflight (server-derived observation).</summary>
    public const string Preflight = "PREFLIGHT";

    /// <summary>Clone-guard guided reactivation (<c>POST /api/activation/clone-guard/reactivate</c>).</summary>
    public const string CloneGuardReactivate = "CLONE_GUARD_REACTIVATE";
}
