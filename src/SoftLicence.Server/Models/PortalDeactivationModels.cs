namespace SoftLicence.Server.Models;

/// <summary>
/// Carries the exact closed Website-to-provider portal-deactivation contract.
/// </summary>
/// <param name="Schema">Exact contract schema identifier.</param>
/// <param name="RequestId">Canonical lowercase UUID used for durable idempotency and correlation.</param>
/// <param name="ProductId">Canonical lowercase provider product UUID.</param>
/// <param name="LicenseId">Canonical lowercase provider licence UUID.</param>
/// <param name="HardwareId">Canonical uppercase ASCII hardware authority.</param>
/// <param name="Reason">Closed deactivation reason.</param>
public sealed record PortalDeactivationRequest(
    string? Schema,
    string? RequestId,
    string? ProductId,
    string? LicenseId,
    string? HardwareId,
    string? Reason);

/// <summary>
/// Returns the bounded terminal result accepted by the Website contract.
/// </summary>
/// <param name="Schema">Exact response schema identifier.</param>
/// <param name="RequestId">Canonical correlation UUID copied from the authenticated request.</param>
/// <param name="Outcome">Terminal <c>deactivated</c> or <c>already_inactive</c> outcome.</param>
public sealed record PortalDeactivationResponse(
    string Schema,
    string RequestId,
    string Outcome);

/// <summary>Wraps a portal-deactivation response and its exact-replay state.</summary>
/// <param name="Response">Bounded terminal response.</param>
/// <param name="Idempotent">True when the response was recovered from durable request storage.</param>
public sealed record PortalDeactivationResult(
    PortalDeactivationResponse Response,
    bool Idempotent);

/// <summary>Attests that this authenticated quota refusal made no deactivation or receipt change.</summary>
/// <param name="Schema">Closed refusal schema.</param>
/// <param name="RequestId">Exact authenticated request correlation.</param>
/// <param name="Code">Stable quota refusal code.</param>
/// <param name="Limit">Positive daily limit from the current provider license type.</param>
/// <param name="ResetAtUtc">Next UTC midnight for the existing inactive-seat counting window.</param>
public sealed record PortalDeactivationQuotaRefusal(string Schema, string RequestId, string Code, int Limit, DateTime ResetAtUtc);

/// <summary>Signals a pre-mutation quota refusal; transaction disposal rolls back before HTTP serialization.</summary>
/// <param name="Refusal">Bounded provider-owned retry information.</param>
public sealed class PortalDeactivationQuotaException(PortalDeactivationQuotaRefusal refusal) : Exception(refusal.Code)
{
    /// <summary>Gets the closed refusal, containing no customer or hardware data.</summary>
    public PortalDeactivationQuotaRefusal Refusal { get; } = refusal;
}
