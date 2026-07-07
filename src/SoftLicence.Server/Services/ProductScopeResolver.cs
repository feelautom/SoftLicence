using Microsoft.EntityFrameworkCore;
using SoftLicence.Server.Data;

namespace SoftLicence.Server.Services;

public static class ProductScopeResolver
{
    public static async Task<List<Guid>> ResolveProductScopeIdsAsync(
        LicenseDbContext db,
        Guid rootProductId,
        CancellationToken cancellationToken = default)
    {
        var scopeIds = new List<Guid> { rootProductId };
        var frontier = new List<Guid> { rootProductId };

        while (frontier.Count > 0)
        {
            var children = await db.Products.AsNoTracking()
                .Where(p => p.ParentProductId.HasValue && frontier.Contains(p.ParentProductId.Value))
                .Select(p => p.Id)
                .ToListAsync(cancellationToken);

            frontier = children
                .Where(id => !scopeIds.Contains(id))
                .ToList();

            scopeIds.AddRange(frontier);
        }

        return scopeIds;
    }
}
