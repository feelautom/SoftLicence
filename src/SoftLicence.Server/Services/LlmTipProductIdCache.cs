using System.Collections.Concurrent;

namespace SoftLicence.Server.Services;

/// <summary>
/// Process-wide, bounded memory of the product identifier resolved for an LLM tips <c>appName</c>
/// (TKT-003573). Without it every usage event ran a product lookup before its insert, so a burst of
/// events doubled the database round trips of the ingestion path.
/// </summary>
/// <remarks>
/// <para>
/// The key is the raw <c>appName</c> compared ordinally, with no trimming or case folding. The database
/// lookup stays the only authority on what an application name matches: two spellings that differ
/// only by case are two entries that each hold the database answer, so the cache never introduces a
/// matching rule the relational query does not have.
/// </para>
/// <para>
/// A found product is kept <see cref="FoundLifetime"/>, an unknown name only
/// <see cref="NotFoundLifetime"/> so a product created afterwards is picked up quickly. A product
/// renamed or deleted is therefore seen at most <see cref="FoundLifetime"/> late; the only effect is
/// the <c>ProductId</c> stored on new feedback rows, never an authorization decision.
/// When <see cref="MaximumEntries"/> is reached the whole map is cleared rather than evicted entry by
/// entry: client-supplied names must not be able to grow memory, and a clear only costs one lookup
/// per name. Thread-safe; registered as a singleton.
/// </para>
/// </remarks>
public sealed class LlmTipProductIdCache
{
    /// <summary>Upper bound of distinct application names kept in memory.</summary>
    public const int MaximumEntries = 256;

    /// <summary>How long a resolved product identifier is reused.</summary>
    public static readonly TimeSpan FoundLifetime = TimeSpan.FromMinutes(5);

    /// <summary>How long an application name with no matching product is remembered as unknown.</summary>
    public static readonly TimeSpan NotFoundLifetime = TimeSpan.FromMinutes(1);

    private readonly ConcurrentDictionary<string, Entry> _entries = new(StringComparer.Ordinal);
    private readonly TimeProvider _timeProvider;

    /// <summary>
    /// Creates an empty cache.
    /// </summary>
    /// <param name="timeProvider">Clock used for expiry; <see cref="TimeProvider.System"/> when null.</param>
    public LlmTipProductIdCache(TimeProvider? timeProvider = null)
    {
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    /// <summary>Number of names currently held, expired ones included until they are read again.</summary>
    public int Count => _entries.Count;

    /// <summary>
    /// Returns the cached product identifier of <paramref name="appName"/> when a live entry exists.
    /// </summary>
    /// <param name="appName">Raw application name, matched ordinally.</param>
    /// <param name="productId">The cached identifier, or null for a name cached as unknown.</param>
    /// <returns>True when a non-expired entry answered; false when the caller must query the database.</returns>
    public bool TryGet(string appName, out Guid? productId)
    {
        if (_entries.TryGetValue(appName, out var entry))
        {
            if (entry.ExpiresAtUtc > _timeProvider.GetUtcNow())
            {
                productId = entry.ProductId;
                return true;
            }

            // Remove only this exact expired entry: a concurrent writer may already have stored a fresh one.
            _entries.TryRemove(new KeyValuePair<string, Entry>(appName, entry));
        }

        productId = null;
        return false;
    }

    /// <summary>
    /// Stores the database answer for <paramref name="appName"/>, replacing any previous entry.
    /// Clears the whole cache first when it already holds <see cref="MaximumEntries"/> names.
    /// </summary>
    /// <param name="appName">Raw application name, matched ordinally.</param>
    /// <param name="productId">Resolved product, or null when no product matched.</param>
    public void Set(string appName, Guid? productId)
    {
        if (_entries.Count >= MaximumEntries && !_entries.ContainsKey(appName))
            _entries.Clear();

        var lifetime = productId.HasValue ? FoundLifetime : NotFoundLifetime;
        _entries[appName] = new Entry(productId, _timeProvider.GetUtcNow() + lifetime);
    }

    /// <summary>
    /// Forgets every cached name, so the next event of each application queries the database again.
    /// Call it after a product is created, renamed or deleted when the change must be seen at once.
    /// </summary>
    public void Clear() => _entries.Clear();

    /// <summary>One cached answer: the product (or null for unknown) and its absolute expiry.</summary>
    private sealed record Entry(Guid? ProductId, DateTimeOffset ExpiresAtUtc);
}
