using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace SoftLicence.Server.Services;

/// <summary>
/// HTTP glue for analytics key authentication. Controllers validate through
/// <see cref="ValidateForRequestAsync"/>, which remembers the refusal reason on the request, then answer
/// with <see cref="Failure"/>: 401 for a missing, unknown, inactive or expired key (unchanged historical
/// body), 403 with the required scope when the key is valid but not allowed on this endpoint.
/// </summary>
public static class AnalyticsApiKeyHttp
{
    /// <summary>Historical 401 body kept byte-identical for existing API consumers.</summary>
    public const string UnauthorizedMessage = "Missing or invalid X-Analytics-Key header.";

    private const string FailureItemKey = "SoftLicence.AnalyticsApiKeyValidation";

    /// <summary>
    /// Validates the request key for one scope and stores a refusal on <paramref name="httpContext"/>.
    /// </summary>
    /// <returns>The key context, or null when the key is refused.</returns>
    public static async Task<AnalyticsApiKeyAuthResult?> ValidateForRequestAsync(
        this AnalyticsApiKeyAuthService authService,
        HttpContext httpContext,
        string? analyticsKey,
        string requiredScope,
        CancellationToken cancellationToken)
    {
        var validation = await authService.ValidateDetailedAsync(
            analyticsKey ?? string.Empty,
            requiredScope,
            httpContext.Connection.RemoteIpAddress?.ToString(),
            cancellationToken);
        if (validation.Auth == null)
            httpContext.Items[FailureItemKey] = validation;
        return validation.Auth;
    }

    /// <summary>
    /// Builds the refusal response for the last failed <see cref="ValidateForRequestAsync"/> call.
    /// The 403 body names the missing scope but never echoes the key or its hash.
    /// </summary>
    public static IActionResult Failure(HttpContext httpContext)
    {
        if (httpContext.Items.TryGetValue(FailureItemKey, out var stored)
            && stored is AnalyticsApiKeyValidation { Failure: AnalyticsApiKeyFailure.MissingScope } validation)
        {
            return new ObjectResult(new
            {
                errorCode = "ANALYTICS_SCOPE_REQUIRED",
                requiredScope = validation.RequiredScope,
                message = $"The analytics key is valid but lacks the '{validation.RequiredScope}' scope required by this endpoint.",
            })
            {
                StatusCode = StatusCodes.Status403Forbidden,
            };
        }

        return new UnauthorizedObjectResult(UnauthorizedMessage);
    }
}
