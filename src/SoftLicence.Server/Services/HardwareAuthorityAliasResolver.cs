using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using SoftLicence.Server.Data;

namespace SoftLicence.Server.Services;

/// <summary>
/// Resolves legacy identifiers only through server-owned relationships established by signed Runtime migrations.
/// </summary>
public interface IHardwareAuthorityAliasResolver
{
    /// <summary>
    /// Resolves a submitted identifier inside one product and license boundary.
    /// </summary>
    /// <param name="productId">Product boundary selected by the validated application request.</param>
    /// <param name="licenseId">License boundary selected by the validated license key.</param>
    /// <param name="submittedHardwareId">Exact client-supplied hardware identifier.</param>
    /// <param name="intent">Operation intent that determines whether an inactive canonical seat may still identify authority.</param>
    /// <param name="cancellationToken">Request cancellation token.</param>
    /// <returns>A direct, resolved, or fail-closed result. A refused result must never be treated as a new submitted machine.</returns>
    Task<HardwareAuthorityResolution> ResolveAsync(
        Guid productId,
        Guid licenseId,
        string submittedHardwareId,
        HardwareAuthorityResolutionIntent intent,
        CancellationToken cancellationToken = default);
}

/// <summary>
/// Identifies whether alias resolution is locating authority for activation, status, or an active-seat mutation.
/// </summary>
public enum HardwareAuthorityResolutionIntent
{
    /// <summary>Allows an inactive canonical seat so activation can reactivate the same seat under normal quota policy.</summary>
    Activation,

    /// <summary>Allows an inactive canonical seat so status can report HARDWARE_NOT_ACTIVATED for the proven authority.</summary>
    StatusCheck,

    /// <summary>Requires the canonical seat to be active before a deactivation mutation can target it.</summary>
    Deactivation
}

/// <summary>
/// Describes the result of a license-scoped hardware authority lookup without exposing alias digests.
/// </summary>
/// <param name="SubmittedHardwareId">Exact identifier received from the client.</param>
/// <param name="EffectiveHardwareId">Identifier that owns the seat and must be used for signing and enforcement.</param>
/// <param name="AliasId">Server alias identifier when compatibility resolution occurred.</param>
public sealed record HardwareAuthorityResolution(
    string SubmittedHardwareId,
    string EffectiveHardwareId,
    Guid? AliasId,
    HardwareAuthorityResolutionStatus Status)
{
    /// <summary>Gets whether a server-authenticated compatibility alias was used.</summary>
    public bool UsedAlias => Status == HardwareAuthorityResolutionStatus.Resolved;

    /// <summary>Gets whether a known alias was refused and must never fall back to a new legacy seat.</summary>
    public bool Refused => Status == HardwareAuthorityResolutionStatus.Refused;
}

/// <summary>
/// Separates unknown direct identities from resolved aliases and known aliases that failed authority validation.
/// </summary>
public enum HardwareAuthorityResolutionStatus
{
    /// <summary>No server-side alias exists, so the submitted identity remains a direct authority candidate.</summary>
    NoAlias,

    /// <summary>A single active alias passed every live server authority check.</summary>
    Resolved,

    /// <summary>A known alias was disabled, policy-blocked, ambiguous, rolled back, or divergent and must fail closed.</summary>
    Refused
}

/// <summary>
/// Configures the bounded legacy alias compatibility window.
/// </summary>
public sealed class HardwareAuthorityAliasOptions
{
    /// <summary>Gets or sets the exact fallback mode, either <c>enabled</c> or <c>off</c>.</summary>
    public string DefaultMode { get; set; } = "enabled";

    /// <summary>Gets or sets exact product-specific overrides, evaluated before the fallback mode.</summary>
    public List<HardwareAuthorityAliasProductOptions> Products { get; set; } = [];
}

/// <summary>
/// Selects the compatibility mode for one canonical product identifier.
/// </summary>
public sealed class HardwareAuthorityAliasProductOptions
{
    /// <summary>Gets or sets the canonical lowercase UUID product identifier.</summary>
    public string ProductId { get; set; } = string.Empty;

    /// <summary>Gets or sets the exact mode, either <c>enabled</c> or <c>off</c>.</summary>
    public string Mode { get; set; } = "off";
}

/// <summary>
/// Rejects ambiguous compatibility modes at startup.
/// </summary>
public sealed class HardwareAuthorityAliasOptionsValidator : IValidateOptions<HardwareAuthorityAliasOptions>
{
    /// <inheritdoc />
    public ValidateOptionsResult Validate(string? name, HardwareAuthorityAliasOptions options)
    {
        if (options.DefaultMode is not ("enabled" or "off"))
            return ValidateOptionsResult.Fail("Hardware authority alias default mode must be exactly 'enabled' or 'off'.");

        var productIds = new HashSet<Guid>();
        foreach (var product in options.Products)
        {
            if (!Guid.TryParseExact(product.ProductId, "D", out var productId)
                || product.ProductId != productId.ToString("D")
                || product.Mode is not ("enabled" or "off")
                || !productIds.Add(productId))
            {
                return ValidateOptionsResult.Fail("Hardware authority alias product policies require unique canonical lowercase UUIDs and exact modes.");
            }
        }

        return ValidateOptionsResult.Success;
    }
}

/// <summary>
/// PostgreSQL-backed alias resolver that compares canonical SHA-256 digests through an indexed equality predicate.
/// </summary>
public sealed class HardwareAuthorityAliasResolver(
    LicenseDbContext db,
    IOptions<HardwareAuthorityAliasOptions> options,
    ILogger<HardwareAuthorityAliasResolver> logger) : IHardwareAuthorityAliasResolver
{
    private static readonly TimeSpan ObservationInterval = TimeSpan.FromHours(1);

    /// <inheritdoc />
    public async Task<HardwareAuthorityResolution> ResolveAsync(
        Guid productId,
        Guid licenseId,
        string submittedHardwareId,
        HardwareAuthorityResolutionIntent intent,
        CancellationToken cancellationToken = default)
    {
        if (!IsCanonicalHardwareId(submittedHardwareId))
            return new HardwareAuthorityResolution(
                submittedHardwareId, submittedHardwareId, null, HardwareAuthorityResolutionStatus.NoAlias);

        var legacyDigest = Sha256(submittedHardwareId);
        var aliases = await db.HardwareAuthorityAliases
            .AsNoTracking()
            .Include(candidate => candidate.Product)
            .Include(candidate => candidate.License)
            .Include(candidate => candidate.LicenseSeat)
            .Include(candidate => candidate.RuntimeEnrollment)
            .Include(candidate => candidate.Binding)
            .Where(candidate =>
                candidate.LicenseId == licenseId
                && candidate.LegacyHardwareIdSha256 == legacyDigest)
            .Take(2)
            .ToListAsync(cancellationToken);
        if (aliases.Count == 0)
            return new HardwareAuthorityResolution(
                submittedHardwareId, submittedHardwareId, null, HardwareAuthorityResolutionStatus.NoAlias);
        if (aliases.Count != 1)
            return new HardwareAuthorityResolution(
                submittedHardwareId, submittedHardwareId, null, HardwareAuthorityResolutionStatus.Refused);

        var alias = aliases[0];
        if (!alias.IsActive || alias.DisabledAtUtc.HasValue || !IsEnabledForProduct(productId))
            return new HardwareAuthorityResolution(
                submittedHardwareId, submittedHardwareId, alias.Id, HardwareAuthorityResolutionStatus.Refused);

        if (alias.Product == null
            || alias.License == null
            || alias.LicenseSeat == null
            || alias.RuntimeEnrollment == null
            || alias.Binding == null)
            return new HardwareAuthorityResolution(
                submittedHardwareId, submittedHardwareId, alias.Id, HardwareAuthorityResolutionStatus.Refused);

        var now = DateTime.UtcNow;
        var seat = alias.LicenseSeat;
        var license = alias.License;
        var enrollment = alias.RuntimeEnrollment;
        var binding = alias.Binding;
        var canonicalDigest = IsCanonicalHardwareId(seat.HardwareId) ? Sha256(seat.HardwareId) : string.Empty;
        var authorityIsCurrent = alias.ProductId == productId
            && alias.Product.Id == productId
            && alias.LicenseId == licenseId
            && license.Id == licenseId
            && license.ProductId == productId
            && license.IsActive
            && license.RevokedAt == null
            && (!license.ExpirationDate.HasValue || license.ExpirationDate.Value > now)
            && seat.Id == alias.LicenseSeatId
            && seat.LicenseId == licenseId
            && (intent != HardwareAuthorityResolutionIntent.Deactivation || seat.IsActive)
            && canonicalDigest == alias.CanonicalHardwareIdSha256
            && enrollment.Id == alias.RuntimeEnrollmentId
            && enrollment.BindingId == alias.BindingId
            && enrollment.ProductId == productId
            && enrollment.LicenseId == licenseId
            && enrollment.LicenseSeatId == seat.Id
            && enrollment.State == "ACTIVE"
            // Alias epochs are minimum authenticated generations. Monotonic progress is valid
            // while rollback and every authority or identity divergence remain fail-closed.
            && enrollment.SecurityEpoch >= alias.SecurityEpoch
            && enrollment.AuthorityEpoch >= alias.AuthorityEpoch
            && enrollment.HardwareIdHash == alias.CanonicalHardwareIdSha256
            && binding.Id == alias.BindingId
            && binding.ProductId == productId
            && binding.LicenseId == licenseId
            && binding.LicenseSeatId == seat.Id
            && binding.InstallationId == enrollment.InstallationId
            && binding.State == "active"
            && binding.HardwareIdHash == alias.CanonicalHardwareIdSha256;
        if (!authorityIsCurrent)
        {
            logger.LogWarning(
                "Hardware authority alias {AliasId} was refused because its server authority diverged.",
                alias.Id);
            return new HardwareAuthorityResolution(
                submittedHardwareId, submittedHardwareId, alias.Id, HardwareAuthorityResolutionStatus.Refused);
        }

        var observationCutoff = now - ObservationInterval;
        var observationUpdated = await db.HardwareAuthorityAliases
            .Where(candidate => candidate.Id == alias.Id
                && candidate.IsActive
                && (!candidate.LastObservedAtUtc.HasValue || candidate.LastObservedAtUtc <= observationCutoff))
            .ExecuteUpdateAsync(setters => setters
                .SetProperty(candidate => candidate.LastObservedAtUtc, now)
                .SetProperty(
                    candidate => candidate.ObservationCount,
                    candidate => candidate.ObservationCount < long.MaxValue
                        ? candidate.ObservationCount + 1
                        : candidate.ObservationCount),
                cancellationToken);
        if (observationUpdated == 1)
        {
            logger.LogInformation(
                "Authenticated hardware authority alias {AliasId} used for product {ProductId}, license {LicenseId}, seat {LicenseSeatId}.",
                alias.Id,
                productId,
                licenseId,
                seat.Id);
        }

        return new HardwareAuthorityResolution(
            submittedHardwareId, seat.HardwareId, alias.Id, HardwareAuthorityResolutionStatus.Resolved);
    }

    /// <summary>
    /// Resolves an exact product override before applying the explicit default compatibility mode.
    /// </summary>
    /// <param name="productId">Product security boundary for the submitted request.</param>
    /// <returns><see langword="true"/> only while legacy alias compatibility is explicitly enabled for the product.</returns>
    private bool IsEnabledForProduct(Guid productId)
    {
        var productPolicy = options.Value.Products.SingleOrDefault(candidate =>
            string.Equals(candidate.ProductId, productId.ToString("D"), StringComparison.Ordinal));
        return (productPolicy?.Mode ?? options.Value.DefaultMode) == "enabled";
    }

    /// <summary>
    /// Tests the exact uppercase 16-character ASCII hexadecimal authority contract.
    /// </summary>
    /// <param name="value">Untrusted identifier to validate without rewriting.</param>
    /// <returns><see langword="true"/> only for the canonical wire representation.</returns>
    internal static bool IsCanonicalHardwareId(string? value) =>
        value is { Length: 16 }
        && value.All(character => character is >= '0' and <= '9' or >= 'A' and <= 'F');

    /// <summary>
    /// Hashes an already validated canonical identifier without case or whitespace rewriting.
    /// </summary>
    /// <param name="value">Canonical identifier whose exact UTF-8 bytes form the digest input.</param>
    /// <returns>A lowercase 64-character SHA-256 hexadecimal digest suitable for indexed persistence.</returns>
    internal static string Sha256(string value) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(value)));
}
