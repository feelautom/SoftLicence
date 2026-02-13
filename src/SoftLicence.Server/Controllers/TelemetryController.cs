using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using SoftLicence.Server.Models;
using SoftLicence.Server.Services;
using SoftLicence.Server.Data;

namespace SoftLicence.Server.Controllers;

[ApiController]
[Route("api/telemetry")]
[Microsoft.AspNetCore.RateLimiting.EnableRateLimiting("PublicAPI")]
public class TelemetryController : ControllerBase
{
    private readonly TelemetryService _telemetryService;
    private readonly IDbContextFactory<LicenseDbContext> _dbFactory;

    public TelemetryController(TelemetryService telemetryService, IDbContextFactory<LicenseDbContext> dbFactory)
    {
        _telemetryService = telemetryService;
        _dbFactory = dbFactory;
    }

    private async Task<bool> IsValidClientAsync(TelemetryBaseRequest req)
    {
        if (string.IsNullOrWhiteSpace(req.AppName) || string.IsNullOrWhiteSpace(req.HardwareId)) return false;
        using var db = await _dbFactory.CreateDbContextAsync();
        return await db.Products.AnyAsync(p => p.Name.ToLower() == req.AppName.ToLower());
    }

    [HttpPost("event")]
    public async Task<IActionResult> PostEvent([FromBody] TelemetryEventRequest req)
    {
        if (!await IsValidClientAsync(req)) return Unauthorized();
        try
        {
            await _telemetryService.SaveEventAsync(req);
            return Ok();
        }
        catch (Exception)
        {
            return Accepted();
        }
    }

    [HttpPost("diagnostic")]
    public async Task<IActionResult> PostDiagnostic([FromBody] TelemetryDiagnosticRequest req)
    {
        if (!await IsValidClientAsync(req)) return Unauthorized();
        try
        {
            await _telemetryService.SaveDiagnosticAsync(req);
            return Ok();
        }
        catch (Exception)
        {
            return Accepted();
        }
    }

    [HttpPost("error")]
    public async Task<IActionResult> PostError([FromBody] TelemetryErrorRequest req)
    {
        if (!await IsValidClientAsync(req)) return Unauthorized();
        try
        {
            await _telemetryService.SaveErrorAsync(req);
            return Ok();
        }
        catch (Exception)
        {
            return Accepted();
        }
    }

    [HttpGet]
    public async Task<IActionResult> GetTelemetry(
        [FromHeader(Name = "X-Product-Key")] string? productKey,
        [FromQuery] int page = 1,
        [FromQuery] int pageSize = 50,
        [FromQuery] TelemetryType? type = null)
    {
        if (string.IsNullOrEmpty(productKey))
        {
            return Unauthorized("Missing X-Product-Key header.");
        }

        var results = await _telemetryService.GetTelemetryForProductAsync(productKey, page, pageSize, type);
        
        // On pourrait vérifier si la liste est vide pour renvoyer 401, 
        // mais le service renvoie déjà une liste vide si la clé est mauvaise.
        // Pour être plus précis sur l'auth :
        if (results.Count == 0 && page == 1)
        {
            // Vérification si le produit existe vraiment
            // (Note: GetTelemetryForProductAsync renvoie vide aussi si pas de logs)
            // On va simplifier pour ce cas.
        }

        return Ok(results);
    }
}
