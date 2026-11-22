using Microsoft.EntityFrameworkCore;
using SoftLicence.Server.Data;

namespace SoftLicence.Server.Services;

/// <summary>Checks the optional per-license refusal before a new key-based activation is admitted.</summary>
public static class LicenseKeyActivationChecker
{
    /// <summary>Closed API error code returned when key-based activation is disabled.</summary>
    public const string RefusalCode = "key_activation_disabled";

    /// <summary>Returns whether the exact license currently refuses key-based activation.</summary>
    /// <param name="db">The request's license database context.</param>
    /// <param name="licenseId">The exact license UUID to check.</param>
    /// <param name="cancellationToken">Cancels the database query.</param>
    /// <returns><see langword="true"/> only when the license has a disabled setting.</returns>
    public static Task<bool> IsDisabledAsync(
        LicenseDbContext db,
        Guid licenseId,
        CancellationToken cancellationToken = default) =>
        db.LicenseKeyActivationSettings
            .AsNoTracking()
            .AnyAsync(
                setting => setting.LicenseId == licenseId && setting.Disabled,
                cancellationToken);
}
