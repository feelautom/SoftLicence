using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using SoftLicence.Server.Data;
using SoftLicence.Server.Services;
using SoftLicence.Server.Services.CloneGuard;

namespace SoftLicence.Server.Controllers;

/// <summary>
/// Single-use control token of the managed licence check (TKT-003615, design TKT-001461): detection of a copied or
/// restored installation and its guided reactivation. Contract: <c>docs/schema/jeton-anti-clonage.md</c>.
/// </summary>
public partial class ActivationController
{
    /// <summary>Logical status of a copy holding a stale or missing token; answered with HTTP 200 like every check status.</summary>
    internal const string DuplicateDetectedStatus = "DUPLICATE_DETECTED";

    /// <summary>Clear message shown by the client next to the reactivation screen (product decision n°1, 12/11/2026).</summary>
    internal const string DuplicateDetectedMessage =
        "Cette installation a été copiée ou restaurée depuis une sauvegarde. Réactivez-la sur ce poste pour continuer ; l'autre copie sera alors arrêtée.";

    /// <summary>Message returned when a guided reactivation is refused because the licence's daily quota is exhausted.</summary>
    internal const string ReactivationLimitMessage =
        "La licence a atteint aujourd'hui son nombre maximal de changements de poste. La copie active reste utilisable ; la réactivation sera possible après minuit UTC.";

    /// <summary>
    /// Evaluates the clone guard member of a check once its logical status is known.
    /// </summary>
    /// <param name="req">Check request; nothing happens when its <see cref="ActivationRequest.CloneGuard"/> is absent.</param>
    /// <param name="license">Licence of the check, with its seats loaded.</param>
    /// <param name="authoritativeHardwareId">Hardware identifier the status was computed for (after alias resolution).</param>
    /// <param name="status">Logical status computed by the check; only <c>VALID</c> is evaluated.</param>
    /// <param name="cloneGuards">Token authority sharing the request context.</param>
    /// <param name="cancellationToken">Request abort token.</param>
    /// <returns>
    /// <see langword="null"/> when the request carried no clone guard (historical answer); <c>NOT_EVALUATED</c> when the
    /// status is not VALID (the client keeps its token); <c>NOT_APPLICABLE</c> when no active seat row matches the
    /// identifier (historical single-field licence); otherwise the decision of <see cref="SeatCloneGuardService"/>.
    /// </returns>
    private async Task<CloneGuardResponse?> EvaluateCloneGuardAsync(
        ActivationRequest req, License license, string authoritativeHardwareId, string status,
        SeatCloneGuardService cloneGuards, CancellationToken cancellationToken)
    {
        if (req.CloneGuard == null)
            return null;
        if (!string.Equals(status, "VALID", StringComparison.Ordinal))
            return new CloneGuardResponse(CloneGuardOutcomes.NotEvaluated, null, false);
        var seat = license.Seats.FirstOrDefault(row => row.IsActive
            && string.Equals(row.HardwareId, authoritativeHardwareId, StringComparison.Ordinal));
        if (seat == null)
            return new CloneGuardResponse(CloneGuardOutcomes.NotApplicable, null, false);
        return await cloneGuards.EvaluateCheckAsync(license, seat, req.CloneGuard, CloneGuardContext(req.AppVersion), cancellationToken);
    }

    /// <summary>
    /// Builds the journal facts of the current request: transport address (as resolved by the forwarded-headers
    /// middleware, never a raw header), client version and server correlation, each bounded to its column length.
    /// </summary>
    /// <param name="appVersion">Client version as received, possibly <see langword="null"/>.</param>
    private CloneGuardRequestContext CloneGuardContext(string? appVersion) => new(
        Bound(HttpContext.Connection.RemoteIpAddress?.ToString(), 50),
        Bound(appVersion, 80),
        Bound(HttpContext.TraceIdentifier, 200));

    /// <summary>Truncates a journal value to its column length; <see langword="null"/> stays <see langword="null"/>.</summary>
    private static string? Bound(string? value, int max) =>
        value == null ? null : value.Length <= max ? value : value[..max];

    /// <summary>
    /// Guided reactivation of a copy answered <c>DUPLICATE_DETECTED</c> (TKT-003615): makes the caller the single active
    /// copy of its seat; the other copy is suspended at its next check.
    /// </summary>
    /// <param name="req">Reactivation request with the caller's hardware identifier, machine evidence and next token.</param>
    /// <param name="cloneGuards">Token authority sharing the request context.</param>
    /// <returns>
    /// Exactly the answer of <c>/api/activation/check</c> for every refusal, because both routes call
    /// <see cref="EvaluateStatusAsync"/>: 400 non-canonical identifier, 404 unknown product or key, and HTTP 200 with
    /// the refusing status (<c>DEVICE_REFUSED</c>, <c>REVOKED</c>, <c>EXPIRED</c>, <c>UPDATE_REQUIRED</c>,
    /// <c>HARDWARE_AUTHORITY_REFUSED</c>, <c>HARDWARE_NOT_ACTIVATED</c>, <c>HARDWARE_MISMATCH</c>,
    /// <c>REQUIRES_ACTIVATION</c>, <c>FREEMIUM_HWID_ALREADY_CONSUMED</c>, ...) and no licence file, without touching the
    /// guard or the quota. Only for status <c>VALID</c>: <c>REACTIVATED</c> with a fresh licence file, or
    /// <c>REACTIVATION_LIMIT_REACHED</c> without licence file when the daily quota is exhausted and the other copy is
    /// alive (nothing changed), or <c>NOT_APPLICABLE</c> when no active seat row matches the identifier.
    /// </returns>
    /// <remarks>
    /// Review 2439 (NO-GO): the first version re-implemented a subset of the check and skipped the single-use refusal,
    /// so a machine refused <c>FREEMIUM_HWID_ALREADY_CONSUMED</c> by the check could obtain a signed file here. The
    /// shared evaluation removes that second list. Never bans, revokes or releases anything; the daily quota is the
    /// licence's single quota (<see cref="SeatChangeQuota"/>), product decision of 16/11/2026.
    /// </remarks>
    [HttpPost("clone-guard/reactivate")]
    public async Task<IActionResult> ReactivateCloneGuard(
        [FromBody] CloneGuardReactivationRequest req,
        [FromServices] SeatCloneGuardService cloneGuards)
    {
        var statusRequest = new ActivationRequest
        {
            LicenseKey = req.LicenseKey,
            HardwareId = req.HardwareId,
            AppName = req.AppName,
            AppId = req.AppId,
            AppVersion = req.AppVersion,
            SystemUuid = req.SystemUuid,
            MachineEvidence = req.MachineEvidence
        };
        var evaluation = new StatusEvaluation();
        var refusal = await EvaluateStatusAsync(statusRequest, Services.MachineEvidenceEndpoints.CloneGuardReactivate, evaluation);
        if (refusal != null)
            return refusal;
        var license = evaluation.License;
        if (!string.Equals(evaluation.Status, "VALID", StringComparison.Ordinal))
        {
            // Same logical refusal as the check, before any guard, quota or signature work.
            return Ok(new { Status = evaluation.Status, LicenseFile = (string?)null, ErrorMessage = evaluation.ErrorMessage });
        }

        var seat = license.Seats.FirstOrDefault(row => row.IsActive
            && string.Equals(row.HardwareId, evaluation.AuthoritativeHardwareId, StringComparison.Ordinal));
        if (seat == null)
        {
            return Ok(new
            {
                Status = evaluation.Status, LicenseFile = (string?)null, ErrorMessage = (string?)null,
                CloneGuard = new CloneGuardResponse(CloneGuardOutcomes.NotApplicable, null, false)
            });
        }

        var outcome = await cloneGuards.ReactivateAsync(
            license, seat, req.NextToken, req.VmGenerationId, CloneGuardContext(req.AppVersion), HttpContext.RequestAborted);
        if (outcome.Outcome == CloneGuardOutcomes.ReactivationLimitReached)
        {
            TagActivationFailure("REACTIVATION_LIMIT_REACHED");
            return Ok(new { Status = "VALID", LicenseFile = (string?)null, ErrorMessage = ReactivationLimitMessage, CloneGuard = outcome });
        }
        if (outcome.Outcome != CloneGuardOutcomes.Reactivated)
            return Ok(new { Status = "VALID", LicenseFile = (string?)null, ErrorMessage = (string?)null, CloneGuard = outcome });

        string? licenseFile = null;
        try
        {
            licenseFile = _signedLicenseFiles.Generate(license, evaluation.SigningHardwareId, BuildFeatures(license.Type?.CustomParams));
        }
        catch (Exception ex)
        {
            // Same tolerance as the check: the reactivation is committed; the client keeps its cached licence file and
            // receives a fresh one at its next check. The cause is logged, never swallowed.
            _logger.LogWarning(ex, "Licence file generation failed after clone guard reactivation of licence {LicenseId}.", license.Id);
        }
        return Ok(new { Status = "VALID", LicenseFile = licenseFile, ErrorMessage = (string?)null, CloneGuard = outcome });
    }
}
