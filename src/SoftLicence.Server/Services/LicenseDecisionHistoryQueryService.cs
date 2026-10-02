using Microsoft.EntityFrameworkCore;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;

namespace SoftLicence.Server.Services;

/// <summary>Reads stored decisions for one already authorized product using exact indexed identity selectors.</summary>
/// <param name="dbFactory">Creates private read contexts; this service changes no licensing state.</param>
public sealed class LicenseDecisionHistoryQueryService(IDbContextFactory<LicenseDbContext> dbFactory)
{
    private const int MaximumRequestSnapshotRows = 1000;

    /// <summary>Reads one exact request in a single bounded SQL query, avoiding offset drift under concurrent inserts.</summary>
    public async Task<IReadOnlyList<LicenseDecisionHistoryProjection>> ReadRequestSnapshotAsync(
        Guid productId, string requestId, CancellationToken cancellationToken)
    {
        if (productId == Guid.Empty || !ValidIdentifier(requestId, 200) || requestId == null)
            throw new ArgumentException("Provide one exact bounded request identifier.");
        await using var db = await dbFactory.CreateDbContextAsync(cancellationToken);
        var rows = await db.LicenseHistories.AsNoTracking().Where(row =>
                row.License!.ProductId == productId && row.Action == "ACTIVATION_DECISION_V1"
                && (row.DecisionOperationId == requestId || row.DecisionCorrelationId == requestId))
            .OrderByDescending(row => row.Timestamp).ThenByDescending(row => row.Id)
            .Take(MaximumRequestSnapshotRows + 1).ToListAsync(cancellationToken);
        if (rows.Count > MaximumRequestSnapshotRows)
            throw new InvalidOperationException("The exact request snapshot exceeds its safe bound.");
        return rows.Select(row => LicenseDecisionHistoryProjection.FromHistory(row, productId, requestId)).ToArray();
    }

    /// <summary>Returns newest stored decisions, preserving unknown observations and excluding other products.</summary>
    /// <param name="productId">Product established by administrator authentication, never by a hardware correlation.</param>
    /// <param name="licenseId">Optional exact licence UUID.</param>
    /// <param name="hardwareId">Optional exact submitted, resolved or correlated HWID; no casing, whitespace or Unicode repair.</param>
    /// <param name="requestId">Optional exact operation or first observed transport correlation ID.</param>
    /// <param name="take">Page size from 1 through 200.</param>
    /// <param name="offset">Offset from 0 through 10000; stable ordering is timestamp then row UUID.</param>
    /// <param name="cancellationToken">Cancels database work; provider failures propagate to the redacted HTTP mapping.</param>
    /// <returns>At most take typed rows. Multiple selectors intersect; no target is an argument error. Old history without decision metadata is not backfilled.</returns>
    public async Task<IReadOnlyList<LicenseDecisionHistoryProjection>> ReadAsync(
        Guid productId, Guid? licenseId, string? hardwareId, string? requestId,
        int take, int offset, CancellationToken cancellationToken)
    {
        if (productId == Guid.Empty || licenseId == Guid.Empty || take is < 1 or > 200 || offset is < 0 or > 10000
            || !ValidIdentifier(hardwareId, 512) || !ValidIdentifier(requestId, 200)
            || (licenseId == null && hardwareId == null && requestId == null))
            throw new ArgumentException("Provide an exact target and valid page bounds (take 1..200, offset 0..10000).");

        await using var db = await dbFactory.CreateDbContextAsync(cancellationToken);
        var query = db.LicenseHistories.AsNoTracking().Where(row =>
            row.License!.ProductId == productId && row.Action == "ACTIVATION_DECISION_V1");
        if (licenseId.HasValue) query = query.Where(row => row.LicenseId == licenseId.Value);
        if (hardwareId != null) query = query.Where(row => row.DecisionSubmittedHardwareId == hardwareId
            || row.DecisionResolvedHardwareId == hardwareId || row.DecisionCorrelatedHardwareId == hardwareId);
        if (requestId != null) query = query.Where(row => row.DecisionOperationId == requestId
            || row.DecisionCorrelationId == requestId);
        var rows = await query.OrderByDescending(row => row.Timestamp).ThenByDescending(row => row.Id)
            .Skip(offset).Take(take).ToListAsync(cancellationToken);
        return rows.Select(row => LicenseDecisionHistoryProjection.FromHistory(row, productId, requestId)).ToArray();
    }

    /// <summary>Accepts absent or bounded nonempty opaque identifiers without controls or leading/trailing whitespace; never normalizes supplied evidence.</summary>
    private static bool ValidIdentifier(string? value, int maximum) => value == null
        || (value.Length > 0 && value.Length <= maximum && !value.Any(char.IsControl)
            && !char.IsWhiteSpace(value[0]) && !char.IsWhiteSpace(value[^1]));
}
