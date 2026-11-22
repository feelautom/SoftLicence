namespace SoftLicence.Server.Services;

/// <summary>
/// Identifies which server-held BugTrace authority (and therefore which BugTrace project) receives the
/// ticket created when an LLM tip is converted (TKT-003093).
/// </summary>
public enum LlmTipBugTraceProject
{
    /// <summary>No project is configured for the tip's product; the conversion must be refused.</summary>
    None,

    /// <summary>
    /// The dedicated, provider-verified T-IA authority (<c>BUGTRACE_TIA_PROJECT_TOKEN</c>), whose token
    /// selects the T-IA-Connect BugTrace project.
    /// </summary>
    TiaConnect
}

/// <summary>
/// Explicit, server-configured mapping from SoftLicence product to the BugTrace project that receives
/// converted LLM tips (TKT-003093, product decision of 21/11/2026).
/// </summary>
/// <remarks>
/// BugTrace chooses the destination project from the project token alone, and SoftLicence only holds
/// tokens in its server configuration, so the mapping lives in configuration rather than in the database.
/// The mapping never guesses from product or application names and never falls back to the legacy
/// SoftLicence token: an unmapped product resolves to <see cref="LlmTipBugTraceProject.None"/>.
/// Configuration key <see cref="TiaProductIdsKey"/> holds product identifiers separated by commas,
/// semicolons or whitespace, each in the exact 36-character hyphenated form (D format, any hexadecimal
/// case). Identifiers are compared as <see cref="Guid"/> values, so casing never changes the result.
/// A malformed entry makes the whole mapping invalid and every conversion is refused, so a typo cannot
/// silently route some products and drop others. The instance is immutable and thread-safe.
/// </remarks>
public sealed class LlmTipBugTraceRouting
{
    /// <summary>Configuration key listing the products whose tips go to the T-IA-Connect project.</summary>
    public const string TiaProductIdsKey = "BUGTRACE_LLM_TIP_TIA_PRODUCT_IDS";

    /// <summary>Accepted list separators; a value pasted one identifier per line or space-separated stays valid.</summary>
    private static readonly char[] Separators = [',', ';', ' ', '\t', '\r', '\n'];

    /// <summary>Products routed to the T-IA-Connect project; emptied when any entry is malformed. Read-only after construction.</summary>
    private readonly HashSet<Guid> _tiaProductIds;

    /// <summary>
    /// Parses the mapping from server configuration once; it is captured for the singleton lifetime.
    /// </summary>
    /// <param name="configuration">Server configuration; a missing or empty key yields an empty, valid mapping.</param>
    public LlmTipBugTraceRouting(IConfiguration configuration)
        : this(configuration[TiaProductIdsKey])
    {
    }

    /// <summary>
    /// Parses a raw mapping value. Used by the configuration constructor and by tests.
    /// </summary>
    /// <param name="tiaProductIds">
    /// Separator-delimited product identifiers; null, empty or whitespace yields an empty, valid mapping.
    /// Any entry that is not an exact D-format GUID, or the empty GUID, marks the mapping invalid.
    /// </param>
    public LlmTipBugTraceRouting(string? tiaProductIds)
    {
        _tiaProductIds = new HashSet<Guid>();
        if (string.IsNullOrWhiteSpace(tiaProductIds))
            return;

        foreach (var entry in tiaProductIds.Split(Separators, StringSplitOptions.RemoveEmptyEntries))
        {
            // Exact D format only: "N", braces or parentheses would hide a copy/paste mistake in the setting.
            if (!Guid.TryParseExact(entry, "D", out var productId) || productId == Guid.Empty)
            {
                IsValid = false;
                _tiaProductIds.Clear();
                return;
            }

            _tiaProductIds.Add(productId);
        }
    }

    /// <summary>
    /// Gets whether the configured value could be parsed. When false, <see cref="Resolve"/> returns
    /// <see cref="LlmTipBugTraceProject.None"/> for every product so no conversion is relayed.
    /// </summary>
    public bool IsValid { get; } = true;

    /// <summary>
    /// Resolves the BugTrace project for a tip's product.
    /// </summary>
    /// <param name="productId">The product linked to the tip; null for a tip with no known product.</param>
    /// <returns>
    /// <see cref="LlmTipBugTraceProject.TiaConnect"/> for an explicitly mapped product of a valid mapping;
    /// otherwise <see cref="LlmTipBugTraceProject.None"/>, which the caller must refuse.
    /// </returns>
    public LlmTipBugTraceProject Resolve(Guid? productId)
    {
        return IsValid && productId is { } id && _tiaProductIds.Contains(id)
            ? LlmTipBugTraceProject.TiaConnect
            : LlmTipBugTraceProject.None;
    }
}

/// <summary>
/// Raised when an LLM tip cannot be converted because no BugTrace project is configured for its product,
/// or because the mapping setting is malformed (TKT-003093). No provider call was made.
/// </summary>
/// <remarks>
/// Deliberately not an <see cref="InvalidOperationException"/>: callers map that type to "BugTrace
/// unavailable" (503), while this refusal is a configuration decision the operator must act on (409).
/// </remarks>
public sealed class LlmTipBugTraceProjectNotConfiguredException : Exception
{
    /// <summary>Stable error code returned by the API and recognised by the admin page.</summary>
    public const string ErrorCode = "LLM_TIP_BUGTRACE_PROJECT_NOT_CONFIGURED";

    /// <summary>Creates the refusal for one product.</summary>
    /// <param name="productId">The tip's product, or null when the tip has no product.</param>
    /// <param name="mappingInvalid">True when the refusal comes from a malformed mapping setting.</param>
    public LlmTipBugTraceProjectNotConfiguredException(Guid? productId, bool mappingInvalid)
        : base(mappingInvalid
            ? $"The {LlmTipBugTraceRouting.TiaProductIdsKey} setting is malformed; no LLM tip can be converted until it is fixed."
            : $"No BugTrace project is configured for product {(productId.HasValue ? productId.Value.ToString("D") : "(none)")}; add it to {LlmTipBugTraceRouting.TiaProductIdsKey} to convert its LLM tips.")
    {
        ProductId = productId;
        MappingInvalid = mappingInvalid;
    }

    /// <summary>Gets the tip's product, or null when the tip has no product.</summary>
    public Guid? ProductId { get; }

    /// <summary>Gets whether the refusal comes from a malformed mapping setting rather than a missing entry.</summary>
    public bool MappingInvalid { get; }
}
