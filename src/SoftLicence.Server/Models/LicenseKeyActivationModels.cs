namespace SoftLicence.Server.Models;

/// <summary>
/// Carries the exact closed publisher-to-provider key-activation-setting contract.
/// </summary>
/// <param name="Schema">Exact contract schema identifier: pose or lift variant.</param>
/// <param name="RequestId">Canonical lowercase UUID used for durable idempotency and correlation.</param>
/// <param name="ProductId">Canonical lowercase provider product UUID.</param>
/// <param name="LicenseId">Canonical lowercase provider license UUID.</param>
public sealed record LicenseKeyActivationRequest(
    string? Schema,
    string? RequestId,
    string? ProductId,
    string? LicenseId);

/// <summary>
/// Returns the bounded terminal result accepted by the publisher contract.
/// </summary>
/// <param name="Schema">Exact response schema identifier matching the request variant.</param>
/// <param name="RequestId">Canonical correlation UUID copied from the authenticated request.</param>
/// <param name="Outcome">Terminal <c>disabled</c>, <c>already_disabled</c>, <c>lifted</c> or <c>already_lifted</c> outcome.</param>
public sealed record LicenseKeyActivationResponse(
    string Schema,
    string RequestId,
    string Outcome);

/// <summary>Wraps a key-activation-setting response and its exact-replay state.</summary>
/// <param name="Response">Bounded terminal response.</param>
/// <param name="Idempotent">True when the response was recovered from stored request state.</param>
public sealed record LicenseKeyActivationResult(
    LicenseKeyActivationResponse Response,
    bool Idempotent);
