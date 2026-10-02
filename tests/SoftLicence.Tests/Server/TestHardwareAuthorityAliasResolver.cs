using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using SoftLicence.Server.Data;
using SoftLicence.Server.Services;

namespace SoftLicence.Tests.Server;

/// <summary>
/// Delegates test resolution to the production resolver using the transaction supplied by the service under test.
/// </summary>
internal sealed class TestHardwareAuthorityAliasResolver : IHardwareAuthorityAliasResolver
{
    /// <summary>Gets the stateless shared test adapter.</summary>
    public static TestHardwareAuthorityAliasResolver Instance { get; } = new();

    /// <inheritdoc />
    public Task<HardwareAuthorityResolution> ResolveAsync(
        Guid productId,
        Guid licenseId,
        string submittedHardwareId,
        HardwareAuthorityResolutionIntent intent,
        CancellationToken cancellationToken = default) =>
        throw new InvalidOperationException("Tests must supply the service transaction to authority resolution.");

    /// <inheritdoc />
    public Task<HardwareAuthorityResolution> ResolveAsync(
        LicenseDbContext authorityDb,
        Guid productId,
        Guid licenseId,
        string submittedHardwareId,
        HardwareAuthorityResolutionIntent intent,
        CancellationToken cancellationToken = default)
    {
        var resolver = new HardwareAuthorityAliasResolver(
            authorityDb,
            Options.Create(new HardwareAuthorityAliasOptions { DefaultMode = "enabled" }),
            NullLogger<HardwareAuthorityAliasResolver>.Instance);
        return resolver.ResolveAsync(
            authorityDb,
            productId,
            licenseId,
            submittedHardwareId,
            intent,
            cancellationToken);
    }
}
