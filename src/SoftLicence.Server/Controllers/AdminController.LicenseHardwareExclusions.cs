using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using SoftLicence.Server.Models;
using SoftLicence.Server.Services;

namespace SoftLicence.Server.Controllers;

public partial class AdminController
{
    /// <summary>Identifies one exact admin lift request; the licence is resolved from the key.</summary>
    /// <param name="RequestId">Canonical UUID used for durable lift idempotency and correlation.</param>
    /// <param name="HardwareId">Canonical uppercase 16-character hardware authority.</param>
    public sealed record AdminHardwareExclusionLiftRequest(Guid RequestId, string HardwareId);

    /// <summary>
    /// Lifts one active licence hardware exclusion from the SoftLicence administration. Lifting
    /// never reactivates anything: the machine can simply try admission again. The actor is the
    /// closed admin value and the licence is resolved from the exact license key.
    /// </summary>
    /// <param name="licenseKey">Exact licence key owned by the authenticated admin caller.</param>
    /// <param name="request">Exact lift identity and hardware identifier.</param>
    /// <param name="exclusions">Shared provider exclusion service.</param>
    [HttpPost("licenses/{licenseKey}/hardware-exclusions/lift")]
    public async Task<IActionResult> LiftHardwareExclusion(
        string licenseKey,
        [FromBody] AdminHardwareExclusionLiftRequest request,
        [FromServices] ILicenseHardwareExclusionService exclusions)
    {
        TagLog("LIFT_HARDWARE_EXCLUSION", licenseKey);
        var (authorized, scopedProductId) = await GetAuthContextAsync();
        if (!authorized)
            return Unauthorized();

        var license = await _db.Licenses
            .AsNoTracking()
            .SingleOrDefaultAsync(candidate => candidate.LicenseKey == licenseKey);
        if (license == null)
            return NotFound(new { error = "license_not_found" });
        if (!await IsLicenseProductInScopeAsync(scopedProductId, license.ProductId, HttpContext.RequestAborted))
            return Unauthorized();

        try
        {
            var response = await exclusions.LiftAsync(
                LicenseHardwareExclusionService.AdminActor,
                string.Empty,
                new LicenseHardwareExclusionLiftRequest(
                    LicenseHardwareExclusionService.LiftRequestSchema,
                    request.RequestId.ToString("D"),
                    license.ProductId.ToString("D"),
                    license.Id.ToString("D"),
                    request.HardwareId),
                HttpContext.RequestAborted);
            return Ok(response);
        }
        catch (DistributionOperationException exception)
        {
            return StatusCode(exception.StatusCode, new { error = exception.ErrorCode });
        }
    }

    /// <summary>
    /// Lists the hardware exclusions of one licence, active ones first. This is a read-only view
    /// carrying no free text and no client identifiers.
    /// </summary>
    /// <param name="licenseKey">Exact licence key owned by the authenticated admin caller.</param>
    /// <param name="includeLifted">Includes lifted exclusions after the active ones.</param>
    /// <param name="requestId">Optional canonical correlation UUID; one is generated when absent.</param>
    /// <param name="exclusions">Shared provider exclusion service.</param>
    [HttpGet("licenses/{licenseKey}/hardware-exclusions")]
    public async Task<IActionResult> ListHardwareExclusions(
        string licenseKey,
        [FromQuery] bool includeLifted = false,
        [FromQuery] Guid? requestId = null,
        [FromServices] ILicenseHardwareExclusionService? exclusions = null)
    {
        TagLog("LIST_HARDWARE_EXCLUSIONS", licenseKey);
        var (authorized, scopedProductId) = await GetAuthContextAsync();
        if (!authorized)
            return Unauthorized();

        var license = await _db.Licenses
            .AsNoTracking()
            .SingleOrDefaultAsync(candidate => candidate.LicenseKey == licenseKey);
        if (license == null)
            return NotFound(new { error = "license_not_found" });
        if (!await IsLicenseProductInScopeAsync(scopedProductId, license.ProductId, HttpContext.RequestAborted))
            return Unauthorized();

        try
        {
            var response = await exclusions!.ListAsync(
                new LicenseHardwareExclusionListRequest(
                    LicenseHardwareExclusionService.ListRequestSchema,
                    (requestId ?? Guid.NewGuid()).ToString("D"),
                    license.ProductId.ToString("D"),
                    license.Id.ToString("D"),
                    includeLifted),
                HttpContext.RequestAborted);
            return Ok(response);
        }
        catch (DistributionOperationException exception)
        {
            return StatusCode(exception.StatusCode, new { error = exception.ErrorCode });
        }
    }
}
