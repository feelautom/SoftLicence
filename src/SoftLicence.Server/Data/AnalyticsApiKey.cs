using System.ComponentModel.DataAnnotations;

namespace SoftLicence.Server.Data;

public class AnalyticsApiKey
{
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();

    public Guid? ProductId { get; set; }
    public Product? Product { get; set; }

    [Required]
    [MaxLength(120)]
    public string Name { get; set; } = string.Empty;

    [Required]
    [MaxLength(32)]
    public string Prefix { get; set; } = string.Empty;

    [Required]
    [MaxLength(128)]
    public string KeyHash { get; set; } = string.Empty;

    [Required]
    [MaxLength(512)]
    public string Scopes { get; set; } = AnalyticsApiKeyScopes.TelemetryRead;

    [Required]
    [MaxLength(32)]
    public string ScopeKind { get; set; } = AnalyticsApiKeyScopeKinds.Product;

    public bool IsActive { get; set; } = true;
    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;
    public DateTime? ExpiresAtUtc { get; set; }
    public DateTime? LastUsedAtUtc { get; set; }

    [MaxLength(64)]
    public string? LastUsedIp { get; set; }
}

public static class AnalyticsApiKeyScopes
{
    public const string TelemetryRead = "telemetry:read";
    public const string SecurityRead = "security:read";
    public const string MultiProductRead = "analytics:multi-product:read";

    /// <summary>
    /// Creates and changes licence types, their parameters and plugin entries through the preview then apply routes
    /// (TKT-002781). Never granted by default: an administrator adds it to an existing key from the key screen.
    /// </summary>
    public const string LicenseTypesWrite = "license-types:write";

    /// <summary>
    /// Publishes an LLM tip to every client or retracts it through <c>POST api/llm-tips-feedback/admin/tips/sharing</c>
    /// (TKT-003574), from the internal network only. Never granted by default: an administrator adds it to an existing
    /// key from the key screen, like <see cref="LicenseTypesWrite"/>.
    /// </summary>
    public const string LlmTipsShare = "llm-tips:share";

    /// <summary>
    /// Returns <paramref name="scopes"/> with <paramref name="scope"/> added or removed, keeping the other scopes in their
    /// order, separated by single spaces. The comparison ignores case, like <c>AnalyticsApiKeyAuthService.HasScope</c>,
    /// so a scope is never stored twice under two spellings.
    /// </summary>
    /// <param name="scopes">Stored scope list (space, comma or semicolon separated).</param>
    /// <param name="scope">Scope to add or remove.</param>
    /// <param name="enabled">True to add, false to remove.</param>
    /// <returns>The new scope list.</returns>
    public static string WithScope(string? scopes, string scope, bool enabled)
    {
        var list = (scopes ?? string.Empty)
            .Split(new[] { ',', ';', ' ' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(item => !string.Equals(item, scope, StringComparison.OrdinalIgnoreCase))
            .ToList();
        if (enabled) list.Add(scope);
        return string.Join(" ", list);
    }
}

public static class AnalyticsApiKeyScopeKinds
{
    public const string Product = "Product";
    public const string Global = "Global";
}
