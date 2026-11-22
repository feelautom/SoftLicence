using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace SoftLicence.Server.Controllers;

public partial class AdminController
{
    /// <summary>Optional administrator request body; the request UUID defaults to a fresh identifier.</summary>
    public sealed record AdminKeyActivationSettingRequest(Guid? RequestId);

    /// <summary>
    /// Disables key-based activation for the license behind the exact key (TKT-002475). Repeating a pose
    /// on an already-disabled license stays idempotent and returns the same terminal without new history.
    /// </summary>
    [HttpPost("licenses/{licenseKey}/key-activation-settings")]
    public async Task<IActionResult> DisableKeyActivationSetting(
        string licenseKey, [FromBody] AdminKeyActivationSettingRequest? request, CancellationToken cancellationToken)
    {
        TagLog("KEY_ACTIVATION_DISABLED", licenseKey);
        return await ApplyKeyActivationSettingAsync(licenseKey, disable: true, request?.RequestId, cancellationToken);
    }

    /// <summary>
    /// Lifts the key-activation refusal of the license behind the exact key (TKT-002475). Lifting a setting
    /// that is absent or already lifted stays idempotent and returns the same terminal without new history.
    /// </summary>
    [HttpPost("licenses/{licenseKey}/key-activation-settings/lift")]
    public async Task<IActionResult> LiftKeyActivationSetting(
        string licenseKey, [FromBody] AdminKeyActivationSettingRequest? request, CancellationToken cancellationToken)
    {
        TagLog("KEY_ACTIVATION_LIFTED", licenseKey);
        return await ApplyKeyActivationSettingAsync(licenseKey, disable: false, request?.RequestId, cancellationToken);
    }

    /// <summary>
    /// Shared admin path of the pose and lift routes: authenticates the admin secret, resolves the license from the
    /// exact key (no case folding, no trimming), enforces the product scope of a product secret, then applies the
    /// command with the closed <c>admin</c> actor.
    /// </summary>
    /// <param name="licenseKey">Exact license key from the route.</param>
    /// <param name="disable"><see langword="true"/> to disable key activation, <see langword="false"/> to lift it.</param>
    /// <param name="requestId">Optional request UUID for idempotent replay; a fresh one is generated when absent.</param>
    /// <param name="cancellationToken">Cancels the lookup and the database work before commit.</param>
    /// <returns>
    /// 200 with the request UUID and outcome; 401 for a missing secret or another product's secret; 404
    /// <c>license_not_found</c>; 503 outside PostgreSQL; or the status and closed code of a service refusal
    /// (400 <c>invalid_request</c>, 404 <c>target_not_found</c>, 409 <c>idempotency_conflict</c>).
    /// </returns>
    private async Task<IActionResult> ApplyKeyActivationSettingAsync(
        string licenseKey, bool disable, Guid? requestId, CancellationToken cancellationToken)
    {
        var (authorized, scopedProductId) = await GetAuthContextAsync();
        if (!authorized) return Unauthorized();
        if (!_db.Database.IsNpgsql())
            return StatusCode(503, new { error = "key_activation_settings_unavailable" });

        // Exact key, as the other admin licence routes: no case folding, no trimming.
        var license = await _db.Licenses.AsNoTracking()
            .SingleOrDefaultAsync(candidate => candidate.LicenseKey == licenseKey, cancellationToken);
        if (license == null)
            return NotFound(new { error = "license_not_found" });
        if (!await IsLicenseProductInScopeAsync(scopedProductId, license.ProductId, cancellationToken))
            return Unauthorized();

        var command = new Services.LicenseKeyActivationCommand(
            requestId ?? Guid.NewGuid(),
            license.ProductId,
            license.Id,
            Services.LicenseKeyActivationSettingService.AdminActor,
            Services.LicenseKeyActivationSettingService.AdminActor);
        try
        {
            var result = disable
                ? await _keyActivationSettings.DisableAsync(command, cancellationToken)
                : await _keyActivationSettings.LiftAsync(command, cancellationToken);
            return Ok(new { RequestId = result.Response.RequestId, Outcome = result.Response.Outcome });
        }
        catch (Services.DistributionOperationException exception)
        {
            // Idempotency conflict (409), unknown target (404) or invalid request (400) keep their status.
            return StatusCode(exception.StatusCode, new { error = exception.ErrorCode });
        }
    }
}
