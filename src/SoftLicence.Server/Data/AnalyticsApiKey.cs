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
}

public static class AnalyticsApiKeyScopeKinds
{
    public const string Product = "Product";
    public const string Global = "Global";
}
