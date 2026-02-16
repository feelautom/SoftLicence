using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using SoftLicence.Server.Models;
using SoftLicence.Server.Services;
using SoftLicence.Server.Data;
using SoftLicence.Server;

namespace SoftLicence.Server.Controllers;

[ApiController]
[Route("api/telemetry")]
[Microsoft.AspNetCore.RateLimiting.EnableRateLimiting("PublicAPI")]
public class TelemetryController : ControllerBase
{
    private readonly TelemetryService _telemetryService;
    private readonly IDbContextFactory<LicenseDbContext> _dbFactory;
    private readonly ILogger<TelemetryController> _logger;

    public TelemetryController(TelemetryService telemetryService, IDbContextFactory<LicenseDbContext> dbFactory, ILogger<TelemetryController> logger)
    {
        _telemetryService = telemetryService;
        _dbFactory = dbFactory;
        _logger = logger;
    }

    private void TagLog(TelemetryBaseRequest req)
    {
        HttpContext.Items[LogKeys.AppName] = req.AppName;
        HttpContext.Items[LogKeys.HardwareId] = req.HardwareId;
        HttpContext.Items[LogKeys.Endpoint] = "TELEMETRY_" + HttpContext.Request.Path.Value?.Split('/').Last().ToUpper();
        HttpContext.Items[LogKeys.Version] = req.Version ?? "Unknown";
    }

    private async Task<bool> IsValidClientAsync(TelemetryBaseRequest req)
    {
        if (string.IsNullOrWhiteSpace(req.AppName) || string.IsNullOrWhiteSpace(req.HardwareId)) return false;
        
        TagLog(req);
        
        using var db = await _dbFactory.CreateDbContextAsync();
        var product = await db.Products.FirstOrDefaultAsync(p => p.Name.ToLower() == req.AppName.ToLower());
        
        if (product != null)
        {
            // Utiliser le nom canonique pour le log
            HttpContext.Items[LogKeys.AppName] = product.Name;
            return true;
        }
        
        return false;
    }

    private string GetClientIp()
    {
        var forwarded = Request.Headers["X-Forwarded-For"].FirstOrDefault();
        if (!string.IsNullOrEmpty(forwarded)) return forwarded.Split(',')[0].Trim();
        return HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown";
    }

    [HttpPost("event")]
    public async Task<IActionResult> PostEvent([FromBody] TelemetryEventRequest req)
    {
        if (!await IsValidClientAsync(req)) return Unauthorized();
        try
        {
            await _telemetryService.SaveEventAsync(req, GetClientIp());
            return Ok();
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Telemetry ingestion failed");
            return Accepted();
        }
    }

    [HttpPost("diagnostic")]
    public async Task<IActionResult> PostDiagnostic([FromBody] TelemetryDiagnosticRequest req)
    {
        if (!await IsValidClientAsync(req)) return Unauthorized();
        try
        {
            await _telemetryService.SaveDiagnosticAsync(req, GetClientIp());
            return Ok();
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Telemetry ingestion failed");
            return Accepted();
        }
    }

    [HttpPost("error")]
    public async Task<IActionResult> PostError([FromBody] TelemetryErrorRequest req)
    {
        if (!await IsValidClientAsync(req)) return Unauthorized();
        try
        {
            await _telemetryService.SaveErrorAsync(req, GetClientIp());
            return Ok();
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Telemetry ingestion failed");
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

        page = Math.Max(1, page);
        pageSize = Math.Clamp(pageSize, 1, 100);

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
