using Microsoft.EntityFrameworkCore;

namespace SoftLicence.Server.Controllers;

public partial class AdminController
{
    /// <summary>
    /// Maximum number of ancestors walked above a product. Real hierarchies have one or two levels (product,
    /// plugin); a longer chain is treated as corrupt and covers nothing beyond the product itself.
    /// </summary>
    internal const int MaxProductHierarchyDepth = 16;

    /// <summary>
    /// Decides whether the admin secret scope covers a licence of <paramref name="licenseProductId"/> on the
    /// routes that resolve one licence by its key (TKT-002551). The global secret covers every licence; a
    /// product secret covers the licences of its own product and of its descendants (sub-products), exactly as
    /// <c>POST /api/admin/licenses</c> accepts the parent secret for a plugin. A sub-product secret never
    /// covers its parent, a sibling or an unrelated product.
    /// </summary>
    /// <param name="scopedProductId">Product of the presented secret, or null for the global secret.</param>
    /// <param name="licenseProductId">Product that owns the licence resolved by the route.</param>
    /// <param name="cancellationToken">Cancels the hierarchy reads.</param>
    /// <returns><see langword="true"/> when the caller may act on the licence; the route refuses otherwise.</returns>
    private async Task<bool> IsLicenseProductInScopeAsync(
        Guid? scopedProductId, Guid licenseProductId, CancellationToken cancellationToken = default) =>
        !scopedProductId.HasValue
        || await IsSameOrDescendantProductAsync(licenseProductId, scopedProductId.Value, cancellationToken);

    /// <summary>
    /// Returns whether <paramref name="productId"/> is <paramref name="ancestorId"/> itself or one of its
    /// descendants, walking up <c>Products.ParentProductId</c> by identifier only (never by name). The walk is
    /// bounded by <see cref="MaxProductHierarchyDepth"/>; a cycle or a deeper chain is refused as a whole, even
    /// when <paramref name="ancestorId"/> appears in it, so that a corrupt hierarchy never widens a scope.
    /// </summary>
    /// <param name="productId">Product to test, for example the owner of a licence or a requested plugin.</param>
    /// <param name="ancestorId">Product whose subtree is allowed.</param>
    /// <param name="cancellationToken">Cancels the hierarchy reads.</param>
    /// <returns><see langword="true"/> for the same product or a descendant within a well-formed chain.</returns>
    /// <remarks>Reads one parent identifier per level without tracking, inside the caller's current transaction.</remarks>
    private async Task<bool> IsSameOrDescendantProductAsync(
        Guid productId, Guid ancestorId, CancellationToken cancellationToken = default)
    {
        if (productId == ancestorId)
            return true;

        var visited = new HashSet<Guid> { productId };
        var found = false;
        var current = productId;
        while (true)
        {
            var parentId = await _db.Products.AsNoTracking()
                .Where(product => product.Id == current)
                .Select(product => product.ParentProductId)
                .FirstOrDefaultAsync(cancellationToken);
            if (!parentId.HasValue)
                return found;
            if (!visited.Add(parentId.Value) || visited.Count > MaxProductHierarchyDepth + 1)
                return false;
            found |= parentId.Value == ancestorId;
            current = parentId.Value;
        }
    }
}
