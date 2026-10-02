using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using SoftLicence.Server.Services;

namespace SoftLicence.Server.Controllers;

/// <summary>Exposes privacy-bounded pre-download hardware decisions to authorized investigations.</summary>
public sealed partial class AnalyticsController
{
    /// <summary>
    /// Authenticates an Analytics reader, resolves its exact product scope, and returns a bounded safe
    /// projection of durable pre-download decisions without recalculating or mutating authority.
    /// </summary>
    /// <remarks>Requires at least one exact selector or a complete UTC period of at most 90 days. Provider read failures return a redacted 503 response.</remarks>
    [HttpGet("support/runtime-distribution-hardware-decisions")]
    public async Task<IActionResult> GetRuntimeDistributionHardwareDecisions(
        [FromHeader(Name = "X-Analytics-Key")] string? analyticsKey,
        [FromQuery] string? requestId = null,
        [FromQuery] Guid? licenseId = null,
        [FromQuery] string? hardwareIdHash = null,
        [FromQuery] string? outcome = null,
        [FromQuery] DateTime? fromUtc = null,
        [FromQuery] DateTime? toUtc = null,
        [FromQuery] int take = 100,
        [FromQuery] int offset = 0,
        [FromQuery] string? productId = null,
        [FromQuery] string? productName = null,
        CancellationToken cancellationToken = default)
    {
        var auth = await AuthenticateAnalyticsAsync(analyticsKey, cancellationToken);
        if (auth == null) return AnalyticsApiKeyHttp.Failure(HttpContext);
        var product = await ResolveAnalyticsProductAsync(auth, productId, productName, cancellationToken);
        if (product.Error != null) return product.Error;
        if (!ValidSelector(requestId, 36)
            || licenseId == Guid.Empty
            || !ValidHash(hardwareIdHash)
            || outcome is not null and not ("accepted" or "auto-unbanned" or "refused")
            || take is < 1 or > 200 || offset is < 0 or > 10000
            || fromUtc.HasValue != toUtc.HasValue
            || fromUtc is not null && (fromUtc.Value.Kind != DateTimeKind.Utc
                || toUtc!.Value.Kind != DateTimeKind.Utc || fromUtc > toUtc
                || toUtc.Value - fromUtc.Value > TimeSpan.FromDays(90))
            || requestId is null && licenseId is null && hardwareIdHash is null
                && outcome is null && fromUtc is null)
            return BadRequest(new { errorCode = "INVALID_RUNTIME_DISTRIBUTION_DECISION_QUERY" });

        try
        {
            await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
            var query = db.RuntimeDistributionHardwareDecisions.AsNoTracking()
                .Where(item => item.ProductId == product.ProductId);
            if (requestId is not null) query = query.Where(item => item.RequestId == requestId);
            if (licenseId is not null) query = query.Where(item => item.LicenseId == licenseId);
            if (hardwareIdHash is not null) query = query.Where(item => item.HardwareIdHash == hardwareIdHash);
            if (outcome is not null) query = query.Where(item => item.Outcome == outcome);
            if (fromUtc is not null) query = query.Where(item => item.CreatedAtUtc >= fromUtc && item.CreatedAtUtc <= toUtc);
            var rows = await query.OrderByDescending(item => item.CreatedAtUtc).ThenBy(item => item.Id)
                .Skip(offset).Take(take).ToListAsync(cancellationToken);
            var items = rows.Select(item => new
            {
                auditId = item.Id,
                item.RequestId,
                item.ClientId,
                item.ProductId,
                item.LicenseId,
                item.GrantRefDigestSha256,
                item.PayloadDigestSha256,
                item.HardwareIdHash,
                item.InstallationIdHash,
                item.KeyThumbprint,
                item.AuthorityMode,
                item.Outcome,
                item.ReasonCode,
                banCategories = JsonSerializer.Deserialize<string[]>(item.BanCategoriesJson) ?? [],
                item.LicenseActive,
                item.LicenseRevoked,
                item.LicenseExpired,
                item.PaidAutoUnbanEligible,
                item.AutoUnbannedCount,
                item.AttemptCount,
                item.CreatedAtUtc,
                item.LastSeenAtUtc
            });
            return Ok(new { productId = product.ProductId, take, offset, items, privacy = "no-raw-hardware-or-customer-data" });
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception)
        {
            return StatusCode(503, new { errorCode = "RUNTIME_DISTRIBUTION_DECISION_REGISTRY_UNAVAILABLE" });
        }
    }

    /// <summary>Accepts absent text or bounded, control-free exact text without trimming or normalization.</summary>
    private static bool ValidSelector(string? value, int maximum) => value is null
        || value.Length is > 0 && value.Length <= maximum && !value.Any(char.IsControl)
            && !char.IsWhiteSpace(value[0]) && !char.IsWhiteSpace(value[^1]);

    /// <summary>Accepts an absent selector or exactly 64 lowercase hexadecimal SHA-256 characters.</summary>
    private static bool ValidHash(string? value) => value is null
        || Regex.IsMatch(value, "^[0-9a-f]{64}$", RegexOptions.CultureInvariant);
}
