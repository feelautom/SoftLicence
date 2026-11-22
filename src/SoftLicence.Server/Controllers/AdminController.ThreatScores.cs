using Microsoft.AspNetCore.Mvc;
using SoftLicence.Server.Services;

namespace SoftLicence.Server.Controllers;

/// <summary>Operator request erasing the threat score of one IP (TKT-002685).</summary>
public sealed class ThreatScoreResetRequest
{
    /// <summary>IPv4 or IPv6 address; the plain and IPv4-mapped forms are both erased.</summary>
    public string? Ip { get; set; }
    /// <summary>Mandatory reason, kept in the reset journal.</summary>
    public string? Reason { get; set; }
    /// <summary>Operator or tool asking for the reset.</summary>
    public string? ResetBy { get; set; }
}

public partial class AdminController
{
    /// <summary>
    /// Lists persisted IP threat scores, highest first. IP scores are global, so a product-scoped admin
    /// secret is refused.
    /// </summary>
    /// <param name="minScore">Minimum score (default 50).</param>
    /// <param name="take">Maximum rows (1..500).</param>
    [HttpGet("threat-scores")]
    public async Task<IActionResult> ListThreatScores([FromQuery] int minScore = 50, [FromQuery] int take = 100)
    {
        var auth = await GetAuthContextAsync();
        if (!auth.Authorized) return Unauthorized();
        if (auth.ScopedProductId.HasValue) return GlobalAdminRequired();

        var rows = await _security.ListThreatScoresAsync(minScore, take);
        TagLog("THREAT_SCORES", $"min={Math.Max(0, minScore)}");
        return Ok(rows);
    }

    /// <summary>Returns the score rows, last known client (masked licence) and recent resets of one IP.</summary>
    /// <param name="ip">IPv4 or IPv6 address.</param>
    [HttpGet("threat-scores/{ip}")]
    public async Task<IActionResult> GetThreatScore(string ip)
    {
        var auth = await GetAuthContextAsync();
        if (!auth.Authorized) return Unauthorized();
        if (auth.ScopedProductId.HasValue) return GlobalAdminRequired();

        try
        {
            var details = await _security.GetThreatScoreDetailsAsync(ip);
            TagLog("THREAT_SCORE", details.IpAddress);
            return Ok(details);
        }
        catch (ThreatScoreResetValidationException exception)
        {
            return BadRequest(new { error = exception.ErrorCode, message = exception.Message });
        }
    }

    /// <summary>
    /// Erases the threat score of one IP in the database and in memory, without restart, and journals the
    /// reset. Bans are unchanged: lift them separately from the Audit page.
    /// </summary>
    /// <param name="request">IP, reason and operator.</param>
    [HttpPost("threat-scores/reset")]
    public async Task<IActionResult> ResetThreatScore([FromBody] ThreatScoreResetRequest request)
    {
        var auth = await GetAuthContextAsync();
        if (!auth.Authorized) return Unauthorized();
        if (auth.ScopedProductId.HasValue) return GlobalAdminRequired();

        try
        {
            var result = await _security.ResetThreatScoreAsync(
                request.Ip ?? string.Empty,
                "admin-api:" + (string.IsNullOrWhiteSpace(request.ResetBy) ? "unnamed" : request.ResetBy.Trim()),
                request.Reason ?? string.Empty);
            TagLog("THREAT_SCORE_RESET", result.IpAddress);
            return Ok(result);
        }
        catch (ThreatScoreResetValidationException exception)
        {
            return BadRequest(new { error = exception.ErrorCode, message = exception.Message });
        }
    }

    private ObjectResult GlobalAdminRequired() =>
        StatusCode(StatusCodes.Status403Forbidden, new
        {
            error = "global_admin_required",
            message = "IP threat scores are global; use the global admin secret."
        });
}
