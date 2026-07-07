using Microsoft.EntityFrameworkCore;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;

namespace SoftLicence.Server.Services;

public sealed class LicenseHardwareVerifierAnalyticsService
{
    private readonly IDbContextFactory<LicenseDbContext> _dbFactory;

    public LicenseHardwareVerifierAnalyticsService(IDbContextFactory<LicenseDbContext> dbFactory)
    {
        _dbFactory = dbFactory;
    }

    public async Task<LicenseHardwareVerificationResponse> VerifyHardwareIdForProductIdAsync(
        Guid productId,
        string hardwareId,
        CancellationToken cancellationToken = default)
    {
        var normalizedHardwareId = NormalizeHardwareId(hardwareId);
        if (normalizedHardwareId == null)
        {
            return new LicenseHardwareVerificationResponse
            {
                Status = "Unknown",
                ReasonCode = "invalid_hardware_id"
            };
        }

        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        var productScopeIds = await ProductScopeResolver.ResolveProductScopeIdsAsync(db, productId, cancellationToken);
        var now = DateTime.UtcNow;

        var seatMatches = await db.LicenseSeats.AsNoTracking()
            .Include(s => s.License)
                .ThenInclude(l => l!.Type)
            .Include(s => s.License)
                .ThenInclude(l => l!.Product)
            .Where(s => s.HardwareId == normalizedHardwareId
                && s.License != null
                && productScopeIds.Contains(s.License.ProductId))
            .ToListAsync(cancellationToken);

        var legacyMatches = await db.Licenses.AsNoTracking()
            .Include(l => l.Type)
            .Include(l => l.Product)
            .Where(l => productScopeIds.Contains(l.ProductId) && l.HardwareId == normalizedHardwareId)
            .ToListAsync(cancellationToken);

        var candidates = new List<LicenseHardwareCandidate>();
        candidates.AddRange(seatMatches.Select(s => new LicenseHardwareCandidate(s.License!, s)));
        candidates.AddRange(legacyMatches.Select(l => new LicenseHardwareCandidate(l, null)));

        if (candidates.Count == 0)
        {
            return new LicenseHardwareVerificationResponse
            {
                HardwareId = normalizedHardwareId,
                ProductId = productId,
                Status = "Unknown",
                ReasonCode = "hardware_id_not_found"
            };
        }

        var active = candidates
            .Where(c => IsActive(c, now))
            .OrderByDescending(c => c.Seat?.LastCheckInAt ?? c.License.ActivationDate ?? c.License.CreationDate)
            .FirstOrDefault();

        if (active != null)
            return BuildResponse(normalizedHardwareId, active, "Active", "active_license_found");

        var bestInactive = candidates
            .OrderBy(c => GetInactivePriority(c, now))
            .ThenByDescending(c => c.Seat?.LastCheckInAt ?? c.License.ActivationDate ?? c.License.CreationDate)
            .First();

        return BuildResponse(normalizedHardwareId, bestInactive, "Inactive", GetInactiveReasonCode(bestInactive, now));
    }

    private static bool IsActive(LicenseHardwareCandidate candidate, DateTime now)
    {
        return candidate.License.IsActive
            && (candidate.License.ExpirationDate == null || candidate.License.ExpirationDate > now)
            && (candidate.Seat == null || candidate.Seat.IsActive);
    }

    private static int GetInactivePriority(LicenseHardwareCandidate candidate, DateTime now)
    {
        var reason = GetInactiveReasonCode(candidate, now);
        return reason switch
        {
            "license_revoked" => 0,
            "license_expired" => 1,
            "seat_inactive" => 2,
            _ => 9
        };
    }

    private static string GetInactiveReasonCode(LicenseHardwareCandidate candidate, DateTime now)
    {
        if (!candidate.License.IsActive)
            return "license_revoked";

        if (candidate.License.ExpirationDate != null && candidate.License.ExpirationDate <= now)
            return "license_expired";

        if (candidate.Seat is { IsActive: false })
            return "seat_inactive";

        return "no_active_license";
    }

    private static LicenseHardwareVerificationResponse BuildResponse(
        string hardwareId,
        LicenseHardwareCandidate candidate,
        string status,
        string reasonCode)
    {
        var license = candidate.License;
        return new LicenseHardwareVerificationResponse
        {
            HardwareId = hardwareId,
            Status = status,
            ReasonCode = reasonCode,
            ProductId = license.ProductId,
            ProductName = license.Product?.Name,
            LicenseId = license.Id,
            UserId = license.Id,
            LicenseType = license.Type?.Slug,
            LicenseTypeName = license.Type?.Name,
            LicenseTypeLabel = GetLicenseTypeLabel(license.Type),
            CustomerEmail = NormalizeOptional(license.CustomerEmail),
            CustomerEmailRedacted = RedactEmail(license.CustomerEmail),
            Company = NormalizeOptional(license.CustomerName),
            ActivationDateUtc = candidate.Seat?.FirstActivatedAt ?? license.ActivationDate,
            ExpirationDateUtc = license.ExpirationDate
        };
    }

    private static string? GetLicenseTypeLabel(LicenseType? type)
    {
        var value = NormalizeOptional(type?.Name) ?? NormalizeOptional(type?.Slug);
        if (value == null)
            return null;

        if (value.Contains("trial", StringComparison.OrdinalIgnoreCase))
            return "Trial";

        if (value.Contains("pro", StringComparison.OrdinalIgnoreCase))
            return "Pro";

        if (value.Contains("enterprise", StringComparison.OrdinalIgnoreCase))
            return "Enterprise";

        if (value.Contains("freemium", StringComparison.OrdinalIgnoreCase))
            return "Freemium";

        return value;
    }

    private static string? NormalizeHardwareId(string? value)
    {
        var trimmed = value?.Trim();
        return string.IsNullOrWhiteSpace(trimmed) ? null : trimmed.ToUpperInvariant();
    }

    private static string? NormalizeOptional(string? value)
    {
        var trimmed = value?.Trim();
        return string.IsNullOrWhiteSpace(trimmed) ? null : trimmed;
    }

    private static string? RedactEmail(string? email)
    {
        var normalized = NormalizeOptional(email);
        if (normalized == null)
            return null;

        var at = normalized.IndexOf('@', StringComparison.Ordinal);
        if (at <= 0)
            return "***";

        var local = normalized[..at];
        var domain = normalized[(at + 1)..];
        var prefix = local.Length <= 2 ? local[..1] : local[..Math.Min(2, local.Length)];
        return $"{prefix}***@{domain}";
    }

    private sealed record LicenseHardwareCandidate(License License, LicenseSeat? Seat);
}
