using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using SoftLicence.Server.Data;
using SoftLicence.Server.Services;

namespace SoftLicence.Server.Controllers;

[ApiController]
[Route("api/analytics/leadops")]
[Microsoft.AspNetCore.RateLimiting.EnableRateLimiting("AdminAPI")]
public sealed class LeadOpsSnapshotController(
    IDbContextFactory<LicenseDbContext> dbFactory,
    AnalyticsApiKeyAuthService apiKeyAuth) : ControllerBase
{
    private const int DefaultLimit = 250;
    private const int MaxLimit = 1000;

    [HttpGet("snapshot")]
    public async Task<IActionResult> GetSnapshot(
        [FromHeader(Name = "X-Analytics-Key")] string? analyticsKey,
        [FromQuery] int limit = DefaultLimit,
        [FromQuery] int page = 1,
        [FromQuery] int? offset = null,
        [FromQuery] string? cursor = null,
        [FromQuery] string? after = null,
        [FromQuery] int telemetryDays = 30,
        [FromQuery] string? productId = null,
        [FromQuery] string? productName = null,
        CancellationToken cancellationToken = default)
    {
        var auth = await apiKeyAuth.ValidateAsync(
            analyticsKey ?? "",
            AnalyticsApiKeyScopes.TelemetryRead,
            HttpContext.Connection.RemoteIpAddress?.ToString(),
            cancellationToken);

        if (auth == null)
            return Unauthorized("Missing or invalid X-Analytics-Key header.");

        limit = Math.Clamp(limit, 1, MaxLimit);
        var resolvedOffset = ResolveOffset(limit, page, offset, cursor, after);
        var resolvedPage = (resolvedOffset / limit) + 1;
        telemetryDays = Math.Clamp(telemetryDays, 1, 90);

        await using var db = await dbFactory.CreateDbContextAsync(cancellationToken);
        var resolvedProduct = await ResolveProductAsync(db, auth, productId, productName, cancellationToken);
        if (resolvedProduct.Error != null)
            return resolvedProduct.Error;

        var resolvedProductId = resolvedProduct.ProductId;
        Response.Headers["X-SoftLicence-Product-Id"] = resolvedProductId.ToString("D");
        Response.Headers["X-SoftLicence-Product-Scope-Mode"] = resolvedProduct.ScopeMode;
        if (!string.IsNullOrWhiteSpace(resolvedProduct.ProductName))
            Response.Headers["X-SoftLicence-Product-Name"] = resolvedProduct.ProductName;

        var now = DateTime.UtcNow;
        var telemetrySince = now.AddDays(-telemetryDays);

        var licensesQuery = db.Licenses.AsNoTracking()
            .Include(x => x.Type)
            .Include(x => x.Seats)
            .Where(x => x.ProductId == resolvedProductId);

        var totalLicensesAvailable = await licensesQuery.CountAsync(cancellationToken);

        var licenses = await licensesQuery
            .OrderByDescending(x => x.CreationDate)
            .ThenByDescending(x => x.Id)
            .Skip(resolvedOffset)
            .Take(limit)
            .ToListAsync(cancellationToken);
        var hasMoreLicenses = resolvedOffset + licenses.Count < totalLicensesAvailable;
        var nextOffset = hasMoreLicenses ? resolvedOffset + licenses.Count : (int?)null;
        var nextPage = hasMoreLicenses ? (nextOffset!.Value / limit) + 1 : (int?)null;

        var hardwareIds = licenses
            .SelectMany(CollectHardwareIds)
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        var telemetryBaseQuery = db.TelemetryRecords.AsNoTracking()
            .Where(x => x.ProductId == resolvedProductId && x.Timestamp >= telemetrySince);

        var telemetryRows = hardwareIds.Count == 0
            ? []
            : await telemetryBaseQuery
                .Where(x => hardwareIds.Contains(x.HardwareId))
                .GroupBy(x => x.HardwareId)
                .Select(g => new LeadOpsTelemetrySummaryDto(
                    g.Key,
                    g.Count(),
                    g.Max(x => x.Timestamp),
                    g.OrderByDescending(x => x.Timestamp).Select(x => x.EventName).FirstOrDefault(),
                    g.OrderByDescending(x => x.Timestamp).Select(x => x.Version).FirstOrDefault(),
                    g.OrderByDescending(x => x.Timestamp).Select(x => x.ClientIp).FirstOrDefault(),
                    g.OrderByDescending(x => x.Timestamp).Select(x => x.Isp).FirstOrDefault()))
                .ToListAsync(cancellationToken);

        var telemetryByHardwareId = telemetryRows.ToDictionary(x => x.HardwareId, StringComparer.OrdinalIgnoreCase);

        var telemetryMachinesAvailable = hardwareIds.Count == 0
            ? 0
            : await telemetryBaseQuery
                .Where(x => hardwareIds.Contains(x.HardwareId))
                .Select(x => x.HardwareId)
                .Distinct()
                .CountAsync(cancellationToken);

        var bannedHardwareBaseQuery = db.BannedHardwareIds.AsNoTracking()
            .Where(x => x.ProductId == resolvedProductId && x.IsActive);

        var bannedHardware = hardwareIds.Count == 0
            ? []
            : await bannedHardwareBaseQuery
                .Where(x => hardwareIds.Contains(x.HardwareId))
                .OrderByDescending(x => x.BannedAt)
                .Take(limit)
                .Select(x => new LeadOpsBannedHardwareDto(
                    x.Id,
                    x.HardwareId,
                    x.BanCategory,
                    x.Reason,
                    x.BannedAt,
                    x.ExpiresAt,
                    x.IsActive))
                .ToListAsync(cancellationToken);

        var bannedHardwareAvailable = hardwareIds.Count == 0
            ? 0
            : await bannedHardwareBaseQuery
                .Where(x => hardwareIds.Contains(x.HardwareId))
                .CountAsync(cancellationToken);

        var bannedComponentsBaseQuery = db.BannedComponents.AsNoTracking()
            .Where(x => x.ProductId == resolvedProductId && x.IsActive);

        var bannedComponentsAvailable = await bannedComponentsBaseQuery.CountAsync(cancellationToken);

        var bannedComponents = await bannedComponentsBaseQuery
            .OrderByDescending(x => x.BannedAt)
            .Take(limit)
            .Select(x => new LeadOpsBannedComponentDto(
                x.Id,
                x.ComponentType,
                x.ComponentHash,
                x.Reason,
                x.BannedAt,
                x.ExpiresAt,
                x.IsActive))
            .ToListAsync(cancellationToken);

        var licenseDtos = licenses
            .Select(license => ToDto(license, now, telemetryByHardwareId))
            .ToList();

        return Ok(new LeadOpsSoftLicenceSnapshotDto(
            now,
            telemetryDays,
            totalLicensesAvailable,
            totalLicensesAvailable,
            licenseDtos.Count,
            limit,
            limit,
            resolvedPage,
            resolvedOffset,
            hasMoreLicenses,
            nextOffset,
            nextPage,
            nextOffset?.ToString(),
            new LeadOpsSnapshotCoverageDto(
                new LeadOpsCollectionCoverageDto(totalLicensesAvailable, licenseDtos.Count, limit, resolvedOffset, hasMoreLicenses, nextOffset, "CreationDate desc, Id desc", "all_product_licenses"),
                new LeadOpsCollectionCoverageDto(telemetryMachinesAvailable, telemetryRows.Count, limit, 0, telemetryRows.Count < telemetryMachinesAvailable, null, "HardwareId", "returned_licenses_hardware_ids"),
                new LeadOpsCollectionCoverageDto(bannedHardwareAvailable, bannedHardware.Count, limit, 0, bannedHardware.Count < bannedHardwareAvailable, null, "BannedAt desc", "returned_licenses_hardware_ids"),
                new LeadOpsCollectionCoverageDto(bannedComponentsAvailable, bannedComponents.Count, limit, 0, bannedComponents.Count < bannedComponentsAvailable, null, "BannedAt desc", "all_product_active_components")),
            new LeadOpsSoftLicenceCountsDto(
                licenseDtos.Count,
                licenseDtos.Count(x => x.Status == "active"),
                licenseDtos.Count(x => x.Status == "expired"),
                licenseDtos.Count(x => x.Status == "revoked"),
                licenseDtos.Sum(x => x.Seats.Count),
                telemetryRows.Count,
                bannedHardware.Count,
                bannedComponents.Count),
            licenseDtos,
            telemetryRows,
            bannedHardware,
            bannedComponents));
    }

    private static async Task<ResolvedLeadOpsProduct> ResolveProductAsync(
        LicenseDbContext db,
        AnalyticsApiKeyAuthResult auth,
        string? productId,
        string? productName,
        CancellationToken cancellationToken)
    {
        var hasProductId = !string.IsNullOrWhiteSpace(productId);
        var hasProductName = !string.IsNullOrWhiteSpace(productName);
        if (hasProductId && hasProductName)
            return ResolvedLeadOpsProduct.BadRequest("Provide either productId or productName, not both.", "PRODUCT_SELECTOR_AMBIGUOUS");

        if (!hasProductId && !hasProductName)
        {
            if (auth.IsGlobal)
            {
                return ResolvedLeadOpsProduct.BadRequest(
                    "Global analytics keys must provide productId or productName for product-scoped endpoints.",
                    "PRODUCT_SELECTOR_REQUIRED");
            }

            if (!auth.ProductId.HasValue)
                return ResolvedLeadOpsProduct.Forbid("The analytics key is not configured for a product.", "PRODUCT_SCOPE_INVALID");

            return new ResolvedLeadOpsProduct(auth.ProductId.Value, null, "configured", null);
        }

        Product? requestedProduct;
        if (hasProductId)
        {
            if (!Guid.TryParse(productId, out var parsedProductId))
                return ResolvedLeadOpsProduct.BadRequest("productId must be a valid UUID.", "PRODUCT_ID_INVALID");

            requestedProduct = await db.Products
                .AsNoTracking()
                .FirstOrDefaultAsync(p => p.Id == parsedProductId, cancellationToken);
        }
        else
        {
            var normalizedProductName = productName!.Trim();
            var matches = await db.Products
                .AsNoTracking()
                .Where(p => p.Name.ToLower() == normalizedProductName.ToLower())
                .Take(2)
                .ToListAsync(cancellationToken);

            if (matches.Count > 1)
                return ResolvedLeadOpsProduct.BadRequest("productName matches multiple products. Use productId.", "PRODUCT_NAME_AMBIGUOUS");

            requestedProduct = matches.SingleOrDefault();
        }

        if (requestedProduct == null)
            return ResolvedLeadOpsProduct.NotFound("Requested product was not found.", "PRODUCT_NOT_FOUND");

        if (!auth.IsGlobal && (!auth.ProductId.HasValue || requestedProduct.Id != auth.ProductId.Value))
        {
            return ResolvedLeadOpsProduct.Forbid("The analytics key is scoped to a different product.", "PRODUCT_SCOPE_FORBIDDEN", new
            {
                configuredProductId = auth.ProductId,
                requestedProductId = requestedProduct.Id
            });
        }

        return new ResolvedLeadOpsProduct(
            requestedProduct.Id,
            requestedProduct.Name,
            auth.IsGlobal ? "explicit-global" : "explicit",
            null);
    }

    private static int ResolveOffset(int limit, int page, int? offset, string? cursor, string? after)
    {
        if (TryParseNonNegative(cursor, out var cursorOffset))
            return cursorOffset;

        if (TryParseNonNegative(after, out var afterOffset))
            return afterOffset;

        if (offset.HasValue)
            return Math.Max(0, offset.Value);

        return Math.Max(0, page - 1) * limit;
    }

    private static bool TryParseNonNegative(string? value, out int result)
    {
        if (int.TryParse(value, out result) && result >= 0)
            return true;

        result = 0;
        return false;
    }

    private static LeadOpsLicenseDto ToDto(
        License license,
        DateTime now,
        IReadOnlyDictionary<string, LeadOpsTelemetrySummaryDto> telemetryByHardwareId)
    {
        var status = ResolveLicenseStatus(license, now);
        var seats = BuildSeats(license, telemetryByHardwareId);
        var lastTelemetry = seats
            .Select(x => x.LastTelemetryUtc)
            .Where(x => x.HasValue)
            .OrderByDescending(x => x)
            .FirstOrDefault();

        return new LeadOpsLicenseDto(
            license.Id,
            RedactKey(license.LicenseKey),
            license.CustomerName,
            license.CustomerEmail,
            license.Reference,
            license.Type?.Slug ?? "",
            license.Type?.Name ?? "",
            license.Type?.IsFree ?? false,
            status,
            license.CreationDate,
            license.ActivationDate,
            license.ExpirationDate,
            license.ValidityDays,
            license.AllowedVersions,
            license.PartnerCode,
            license.MaxSeats,
            license.RecoveryCount,
            license.HasUninstallEvent,
            license.LastUninstallAt,
            lastTelemetry,
            seats);
    }

    private static List<LeadOpsLicenseSeatDto> BuildSeats(
        License license,
        IReadOnlyDictionary<string, LeadOpsTelemetrySummaryDto> telemetryByHardwareId)
    {
        var seats = license.Seats
            .Where(x => !string.IsNullOrWhiteSpace(x.HardwareId))
            .Select(seat =>
            {
                telemetryByHardwareId.TryGetValue(seat.HardwareId, out var telemetry);
                return new LeadOpsLicenseSeatDto(
                    seat.Id,
                    seat.HardwareId,
                    seat.MachineName,
                    seat.AppVersion,
                    seat.IsActive,
                    seat.FirstActivatedAt,
                    seat.LastCheckInAt,
                    seat.UnlinkedAt,
                    telemetry?.LastTelemetryUtc,
                    telemetry?.LastEventName,
                    telemetry?.LastVersion,
                    telemetry?.ClientIp,
                    telemetry?.Isp,
                    telemetry?.EventCount ?? 0);
            })
            .ToList();

        if (!string.IsNullOrWhiteSpace(license.HardwareId) &&
            seats.All(x => !string.Equals(x.HardwareId, license.HardwareId, StringComparison.OrdinalIgnoreCase)))
        {
            telemetryByHardwareId.TryGetValue(license.HardwareId, out var telemetry);
            seats.Add(new LeadOpsLicenseSeatDto(
                Guid.Empty,
                license.HardwareId,
                null,
                null,
                license.IsActive,
                license.ActivationDate,
                null,
                null,
                telemetry?.LastTelemetryUtc,
                telemetry?.LastEventName,
                telemetry?.LastVersion,
                telemetry?.ClientIp,
                telemetry?.Isp,
                telemetry?.EventCount ?? 0));
        }

        return seats;
    }

    private static IEnumerable<string> CollectHardwareIds(License license)
    {
        if (!string.IsNullOrWhiteSpace(license.HardwareId))
            yield return license.HardwareId;

        foreach (var seat in license.Seats)
        {
            if (!string.IsNullOrWhiteSpace(seat.HardwareId))
                yield return seat.HardwareId;
        }
    }

    private static string ResolveLicenseStatus(License license, DateTime now)
    {
        if (!license.IsActive || license.RevokedAt.HasValue)
            return "revoked";

        if (license.ExpirationDate.HasValue && license.ExpirationDate.Value <= now)
            return "expired";

        return "active";
    }

    private static string RedactKey(string? key)
    {
        if (string.IsNullOrWhiteSpace(key))
            return "";

        var compact = key.Replace("-", "").Replace(" ", "");
        if (compact.Length <= 8)
            return "***";

        return $"{compact[..4]}...{compact[^4..]}";
    }

    private sealed record ResolvedLeadOpsProduct(Guid ProductId, string? ProductName, string ScopeMode, IActionResult? Error)
    {
        public static ResolvedLeadOpsProduct BadRequest(string message, string code)
        {
            return new ResolvedLeadOpsProduct(Guid.Empty, null, "error", new BadRequestObjectResult(new
            {
                errorCode = code,
                message
            }));
        }

        public static ResolvedLeadOpsProduct Forbid(string message, string code, object? details = null)
        {
            return new ResolvedLeadOpsProduct(Guid.Empty, null, "error", new ObjectResult(new
            {
                errorCode = code,
                message,
                details
            })
            {
                StatusCode = StatusCodes.Status403Forbidden
            });
        }

        public static ResolvedLeadOpsProduct NotFound(string message, string code)
        {
            return new ResolvedLeadOpsProduct(Guid.Empty, null, "error", new NotFoundObjectResult(new
            {
                errorCode = code,
                message
            }));
        }
    }
}

public sealed record LeadOpsSoftLicenceSnapshotDto(
    DateTime GeneratedAtUtc,
    int TelemetryDays,
    int TotalAvailable,
    int TotalLicensesAvailable,
    int Returned,
    int Limit,
    int PageSize,
    int Page,
    int Offset,
    bool HasMore,
    int? NextOffset,
    int? NextPage,
    string? NextCursor,
    LeadOpsSnapshotCoverageDto Coverage,
    LeadOpsSoftLicenceCountsDto Counts,
    IReadOnlyList<LeadOpsLicenseDto> Licenses,
    IReadOnlyList<LeadOpsTelemetrySummaryDto> Telemetry,
    IReadOnlyList<LeadOpsBannedHardwareDto> BannedHardware,
    IReadOnlyList<LeadOpsBannedComponentDto> BannedComponents);

public sealed record LeadOpsSnapshotCoverageDto(
    LeadOpsCollectionCoverageDto Licenses,
    LeadOpsCollectionCoverageDto Telemetry,
    LeadOpsCollectionCoverageDto BannedHardware,
    LeadOpsCollectionCoverageDto BannedComponents);

public sealed record LeadOpsCollectionCoverageDto(
    int TotalAvailable,
    int Returned,
    int Limit,
    int Offset,
    bool HasMore,
    int? NextOffset,
    string OrderBy,
    string Scope);

public sealed record LeadOpsSoftLicenceCountsDto(
    int Licenses,
    int ActiveLicenses,
    int ExpiredLicenses,
    int RevokedLicenses,
    int Seats,
    int TelemetryMachines,
    int ActiveHardwareBans,
    int ActiveComponentBans);

public sealed record LeadOpsLicenseDto(
    Guid Id,
    string LicenseKeyRedacted,
    string CustomerName,
    string CustomerEmail,
    string? Reference,
    string LicenseTypeSlug,
    string LicenseTypeName,
    bool IsFree,
    string Status,
    DateTime CreationDateUtc,
    DateTime? ActivationDateUtc,
    DateTime? ExpirationDateUtc,
    int? ValidityDays,
    string AllowedVersions,
    string? PartnerCode,
    int MaxSeats,
    int RecoveryCount,
    bool HasUninstallEvent,
    DateTime? LastUninstallAtUtc,
    DateTime? LastTelemetryUtc,
    IReadOnlyList<LeadOpsLicenseSeatDto> Seats);

public sealed record LeadOpsLicenseSeatDto(
    Guid Id,
    string HardwareId,
    string? MachineName,
    string? AppVersion,
    bool IsActive,
    DateTime? FirstActivatedAtUtc,
    DateTime? LastCheckInAtUtc,
    DateTime? UnlinkedAtUtc,
    DateTime? LastTelemetryUtc,
    string? LastEventName,
    string? LastVersion,
    string? ClientIp,
    string? Isp,
    int EventCount);

public sealed record LeadOpsTelemetrySummaryDto(
    string HardwareId,
    int EventCount,
    DateTime LastTelemetryUtc,
    string? LastEventName,
    string? LastVersion,
    string? ClientIp,
    string? Isp);

public sealed record LeadOpsBannedHardwareDto(
    Guid Id,
    string HardwareId,
    string? Category,
    string Reason,
    DateTime BannedAtUtc,
    DateTime? ExpiresAtUtc,
    bool IsActive);

public sealed record LeadOpsBannedComponentDto(
    Guid Id,
    string ComponentType,
    string ComponentHash,
    string Reason,
    DateTime BannedAtUtc,
    DateTime? ExpiresAtUtc,
    bool IsActive);
