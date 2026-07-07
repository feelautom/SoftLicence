using Microsoft.EntityFrameworkCore;
using SoftLicence.Server.Data;

namespace SoftLicence.Server.Services;

public class SeatCleanupService
{
    private readonly LicenseDbContext _db;
    private readonly ILogger<SeatCleanupService> _logger;

    public SeatCleanupService(LicenseDbContext db, ILogger<SeatCleanupService> logger)
    {
        _db = db;
        _logger = logger;
    }

    /// <summary>
    /// Unlinks a HWID from all other active licenses of the same product.
    /// The license identified by keepLicenseId "wins" and keeps the seat.
    /// </summary>
    public async Task<List<string>> UnlinkHwidFromOtherProductLicensesAsync(
        string hardwareId, Guid keepLicenseId, Guid productId)
    {
        var conflictingSeats = await _db.LicenseSeats
            .Include(s => s.License)
            .Where(s => s.HardwareId == hardwareId
                && s.IsActive
                && s.LicenseId != keepLicenseId
                && s.License!.ProductId == productId)
            .ToListAsync();

        var unlinkedFromKeys = new List<string>();
        foreach (var seat in conflictingSeats)
        {
            seat.IsActive = false;
            seat.UnlinkedAt = DateTime.UtcNow;
            unlinkedFromKeys.Add(seat.License!.LicenseKey);

            _db.LicenseHistories.Add(new LicenseHistory
            {
                LicenseId = seat.LicenseId,
                Action = HistoryActions.AutoUnlinkedProductScope,
                Details = $"HWID {hardwareId} auto-unlinked: activated on license {keepLicenseId} (same product)",
                PerformedBy = "System",
                Timestamp = DateTime.UtcNow
            });

            _logger.LogInformation(
                "Auto-unlinked HWID {HardwareId} from license {LicenseKey} (product scope enforcement)",
                hardwareId, seat.License.LicenseKey);
        }

        if (conflictingSeats.Count > 0)
            await _db.SaveChangesAsync();

        return unlinkedFromKeys;
    }
}
