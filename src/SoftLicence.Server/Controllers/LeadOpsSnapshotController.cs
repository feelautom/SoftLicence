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
        [FromQuery] int telemetryDays = 30,
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
        telemetryDays = Math.Clamp(telemetryDays, 1, 90);

        await using var db = await dbFactory.CreateDbContextAsync(cancellationToken);
        var now = DateTime.UtcNow;
        var telemetrySince = now.AddDays(-telemetryDays);

        var licenses = await db.Licenses.AsNoTracking()
            .Include(x => x.Type)
            .Include(x => x.Seats)
            .Where(x => x.ProductId == auth.ProductId)
            .OrderByDescending(x => x.CreationDate)
            .Take(limit)
            .ToListAsync(cancellationToken);

        var hardwareIds = licenses
            .SelectMany(CollectHardwareIds)
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        var telemetryRows = hardwareIds.Count == 0
            ? []
            : await db.TelemetryRecords.AsNoTracking()
                .Where(x => x.ProductId == auth.ProductId &&
                            x.Timestamp >= telemetrySince &&
                            hardwareIds.Contains(x.HardwareId))
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

        var bannedHardware = hardwareIds.Count == 0
            ? []
            : await db.BannedHardwareIds.AsNoTracking()
                .Where(x => x.ProductId == auth.ProductId &&
                            x.IsActive &&
                            hardwareIds.Contains(x.HardwareId))
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

        var bannedComponents = await db.BannedComponents.AsNoTracking()
            .Where(x => x.ProductId == auth.ProductId && x.IsActive)
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
}

public sealed record LeadOpsSoftLicenceSnapshotDto(
    DateTime GeneratedAtUtc,
    int TelemetryDays,
    LeadOpsSoftLicenceCountsDto Counts,
    IReadOnlyList<LeadOpsLicenseDto> Licenses,
    IReadOnlyList<LeadOpsTelemetrySummaryDto> Telemetry,
    IReadOnlyList<LeadOpsBannedHardwareDto> BannedHardware,
    IReadOnlyList<LeadOpsBannedComponentDto> BannedComponents);

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
