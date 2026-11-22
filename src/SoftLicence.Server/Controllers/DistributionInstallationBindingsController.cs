using System.Security.Cryptography;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using SoftLicence.Server.Models;
using SoftLicence.Server.Services;

namespace SoftLicence.Server.Controllers;

/// <summary>
/// Server-to-server boundary of the installation flow driven by the main distribution client: hardware authority,
/// entitlement issue, installation binding finalize and invalidate, source and finalize authority resolution.
/// Every route authenticates the exact request bytes (PS256 signature, nonce, product and network scope) and then
/// requires <see cref="DistributionS2SPrincipal.MayDriveInstallation"/> (TKT-003162): a dedicated S2S identity gets
/// 403 <c>installation_not_authorized</c> before any lookup or write.
/// </summary>
[ApiController]
[EnableRateLimiting("DistributionS2SAPI")]
public sealed class DistributionInstallationBindingsController : ControllerBase
{
    private const int MaximumBodyBytes = 32 * 1024;
    private static readonly JsonSerializerOptions RequestJsonOptions = new(JsonSerializerDefaults.Web)
    {
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow
    };

    private readonly IDistributionS2SAuthenticationService _authentication;
    private readonly IDistributionInstallationBindingService _bindings;
    /// <summary>Owns transient hardware derivation and ban decisions outside binding persistence.</summary>
    private readonly IRuntimeDistributionPreflightService _preflight;
    private readonly ILogger<DistributionInstallationBindingsController> _logger;

    /// <summary>
    /// Creates the authenticated distribution boundary. The hardware authority service remains
    /// separate from binding mutation so raw observations cannot enter durable binding state.
    /// </summary>
    public DistributionInstallationBindingsController(
        IDistributionS2SAuthenticationService authentication,
        IDistributionInstallationBindingService bindings,
        IRuntimeDistributionPreflightService preflight,
        ILogger<DistributionInstallationBindingsController> logger,
        IFinalizeAuthorityPairResolver? finalizeAuthorityPairs = null)
    {
        _authentication = authentication;
        _bindings = bindings;
        _preflight = preflight;
        _logger = logger;
        _finalizeAuthorityPairs = finalizeAuthorityPairs;
    }

    private readonly IFinalizeAuthorityPairResolver? _finalizeAuthorityPairs;

    /// <summary>
    /// TKT-001296: authenticates the exact request bytes, reserves the S2S nonce, and answers whether the
    /// identifier a Desktop presents at Finalize and the digest frozen on the grant designate the same
    /// machine through one authenticated alias pair. Digest-only response; malformed input fails closed.
    /// A principal without <see cref="DistributionS2SPrincipal.MayDriveInstallation"/> gets 403
    /// <c>installation_not_authorized</c> before the resolver runs (TKT-003162).
    /// </summary>
    /// <param name="cancellationToken">Cancels request reading, authentication, and provider lookup.</param>
    /// <returns>The closed pair resolution or a bounded JSON error.</returns>
    [HttpPost("/api/internal/v1/distribution-installation-bindings/finalize-authority/resolve")]
    public async Task<IActionResult> FinalizeAuthorityPair(CancellationToken cancellationToken)
    {
        Response.Headers.CacheControl = "no-store, max-age=0";
        Response.Headers.Pragma = "no-cache";
        if (_finalizeAuthorityPairs is null)
            return StatusCode(StatusCodes.Status503ServiceUnavailable, new DistributionApiError("service_unavailable"));
        try
        {
            var exactBody = await ReadExactBodyAsync(Request, cancellationToken);
            var productId = ExtractProductIdForAuthentication(exactBody);
            var principal = await _authentication.AuthenticateAndReserveNonceAsync(
                HttpContext, exactBody, productId, cancellationToken);
            if (!principal.MayDriveInstallation)
                return InstallationNotAuthorized();
            return Ok(await _finalizeAuthorityPairs.ResolveAsync(
                principal.ClientId, Digest(exactBody),
                Deserialize<FinalizeAuthorityPairRequest>(exactBody), cancellationToken));
        }
        catch (DistributionS2SAuthenticationException exception)
        {
            return StatusCode(exception.StatusCode, new DistributionApiError(exception.ErrorCode));
        }
        catch (DistributionOperationException exception)
        {
            return StatusCode(exception.StatusCode, new DistributionApiError(exception.ErrorCode, exception.ReasonCode));
        }
        catch (InvalidDataException)
        {
            return BadRequest(new DistributionApiError("invalid_request"));
        }
        catch (JsonException)
        {
            return BadRequest(new DistributionApiError("invalid_request"));
        }
        catch (Exception exception) when (!cancellationToken.IsCancellationRequested
            // TKT-004085: an assignment-trigger refusal is answered as its named code by ApiExceptionSafetyNetMiddleware.
            && !AssignmentRefusals.IsTriggerRefusal(exception))
        {
            return StatusCode(StatusCodes.Status500InternalServerError, new DistributionApiError("internal_error"));
        }
    }

    /// <summary>
    /// Authenticates the exact request bytes, reserves the S2S nonce, and evaluates server-owned
    /// machine authority before any payload lease is issued. Responses and middleware logs exclude
    /// raw observations; malformed, banned, or unavailable authority fails closed. A principal without
    /// <see cref="DistributionS2SPrincipal.MayDriveInstallation"/> gets 403 <c>installation_not_authorized</c>
    /// before any ban or hardware decision is evaluated (TKT-003162).
    /// </summary>
    /// <param name="cancellationToken">Cancels request reading, authentication, and provider lookup.</param>
    /// <returns>An opaque accepted digest or a bounded JSON error.</returns>
    [HttpPost("/api/internal/distribution-installation-bindings/hardware-authority")]
    public async Task<IActionResult> RuntimePreflight(CancellationToken cancellationToken)
    {
        Response.Headers.CacheControl = "no-store, max-age=0";
        Response.Headers.Pragma = "no-cache";
        try
        {
            var exactBody = await ReadExactBodyAsync(Request, cancellationToken);
            var productId = ExtractProductIdForAuthentication(exactBody);
            var principal = await _authentication.AuthenticateAndReserveNonceAsync(
                HttpContext, exactBody, productId, cancellationToken);
            if (!principal.MayDriveInstallation)
                return InstallationNotAuthorized();
            return Ok(await _preflight.EvaluateAsync(
                principal.ClientId, Digest(exactBody),
                Deserialize<RuntimeDistributionPreflightRequest>(exactBody), cancellationToken));
        }
        // Diagnostic volontaire (TKT-001154, conserve pour TKT-001277/TKT-001294) : capture detaillee des
        // exceptions du preflight materiel ; son retrait est une decision explicite, pas un nettoyage.
        catch (DistributionS2SAuthenticationException exception)
        {
            _logger.LogWarning(exception,
                "TEMP-DIAG hardware-authority auth exception errorCode={ErrorCode} status={StatusCode} remoteIp={RemoteIp}",
                exception.ErrorCode, exception.StatusCode, HttpContext.Connection.RemoteIpAddress);
            return StatusCode(exception.StatusCode, new DistributionApiError(exception.ErrorCode));
        }
        catch (DistributionOperationException exception)
        {
            _logger.LogWarning(exception,
                "TEMP-DIAG hardware-authority operation exception errorCode={ErrorCode} status={StatusCode} remoteIp={RemoteIp}",
                exception.ErrorCode, exception.StatusCode, HttpContext.Connection.RemoteIpAddress);
            // UUID refusals expose only AR-xx. VM policy exposes its explanatory message, never its internal reason.
            // TKT-004106: a service_unavailable caused by an assignment state to reconcile publishes that bounded reason;
            // not_eligible and every other refusal of this anti-piracy endpoint stay without reason.
            var publicReason = exception.ErrorCode == RuntimeDistributionPreflightService.DeviceRefusedErrorCode
                ? exception.ReasonCode
                : exception.ErrorCode == "service_unavailable"
                    ? AssignmentRefusals.PublicReasonCode(exception.ErrorCode, exception.ReasonCode)
                    : null;
            return StatusCode(exception.StatusCode, new DistributionApiError(exception.ErrorCode,
                publicReason, VirtualMachinePolicy.Message(exception.ErrorCode)));
        }
        catch (InvalidDataException exception)
        {
            _logger.LogWarning(exception,
                "TEMP-DIAG hardware-authority invalid data remoteIp={RemoteIp}", HttpContext.Connection.RemoteIpAddress);
            return BadRequest(new DistributionApiError("invalid_request"));
        }
        catch (JsonException exception)
        {
            _logger.LogWarning(exception,
                "TEMP-DIAG hardware-authority json exception remoteIp={RemoteIp}", HttpContext.Connection.RemoteIpAddress);
            return BadRequest(new DistributionApiError("invalid_request"));
        }
        catch (Exception exception) when (!cancellationToken.IsCancellationRequested)
        {
            _logger.LogError(exception,
                "TEMP-DIAG hardware-authority unexpected exception type={ExceptionType} remoteIp={RemoteIp}",
                exception.GetType().FullName, HttpContext.Connection.RemoteIpAddress);
            return StatusCode(StatusCodes.Status503ServiceUnavailable,
                new DistributionApiError("service_unavailable"));
        }
    }

    /// <summary>
    /// Resolves the bounded Runtime source authority for Website Finalize construction. Read-only; a principal
    /// without <see cref="DistributionS2SPrincipal.MayDriveInstallation"/> gets 403
    /// <c>installation_not_authorized</c> before the lookup (TKT-003162).
    /// </summary>
    /// <param name="cancellationToken">Cancels authentication or the read-only provider lookup.</param>
    /// <returns>A bounded authority response or stable API error.</returns>
    [HttpPost("/api/internal/v1/distribution-installation-bindings/source-authority/resolve")]
    public async Task<IActionResult> ResolveRuntimeSource(CancellationToken cancellationToken)
    {
        try
        {
            var exactBody = await ReadExactBodyAsync(Request, cancellationToken);
            var productId = ExtractProductIdForAuthentication(exactBody);
            var principal = await _authentication.AuthenticateAndReserveNonceAsync(
                HttpContext, exactBody, productId, cancellationToken);
            if (!principal.MayDriveInstallation)
                return InstallationNotAuthorized();
            var request = Deserialize<DistributionRuntimeSourceResolutionRequest>(exactBody);
            var response = await _bindings.ResolveRuntimeSourceAsync(
                principal.ClientId, request, cancellationToken);
            return Ok(response);
        }
        catch (DistributionS2SAuthenticationException exception)
        {
            return StatusCode(exception.StatusCode, new DistributionApiError(exception.ErrorCode));
        }
        catch (DistributionOperationException exception)
        {
            return StatusCode(exception.StatusCode, new DistributionApiError(exception.ErrorCode, exception.ReasonCode));
        }
        catch (InvalidDataException)
        {
            return BadRequest(new DistributionApiError("invalid_request"));
        }
        catch (JsonException)
        {
            return BadRequest(new DistributionApiError("invalid_request"));
        }
        catch (Exception exception) when (!cancellationToken.IsCancellationRequested
            // TKT-004085: an assignment-trigger refusal is answered as its named code by ApiExceptionSafetyNetMiddleware.
            && !AssignmentRefusals.IsTriggerRefusal(exception))
        {
            return StatusCode(StatusCodes.Status500InternalServerError, new DistributionApiError("internal_error"));
        }
    }

    /// <summary>
    /// Issues, or replays idempotently, the installation entitlement of the authenticated distribution client for
    /// the exact request digest. A principal without <see cref="DistributionS2SPrincipal.MayDriveInstallation"/>
    /// gets 403 <c>installation_not_authorized</c> before any write (TKT-003162).
    /// </summary>
    /// <param name="cancellationToken">Cancels body reading, authentication, or provider work before commit.</param>
    /// <returns>201 for a new entitlement, 200 for an exact replay, or a bounded JSON error.</returns>
    [HttpPost("/api/internal/v1/distribution-entitlements/issue")]
    public async Task<IActionResult> IssueEntitlement(CancellationToken cancellationToken)
    {
        try
        {
            var exactBody = await ReadExactBodyAsync(Request, cancellationToken);
            var productId = ExtractProductIdForAuthentication(exactBody);
            var principal = await _authentication.AuthenticateAndReserveNonceAsync(
                HttpContext, exactBody, productId, cancellationToken);
            if (!principal.MayDriveInstallation)
                return InstallationNotAuthorized();
            var request = Deserialize<DistributionEntitlementIssueRequest>(exactBody);
            var result = await _bindings.IssueEntitlementAsync(
                principal.ClientId, Digest(exactBody), request, cancellationToken);
            return StatusCode(result.Idempotent ? StatusCodes.Status200OK : StatusCodes.Status201Created, result.Response);
        }
        catch (DistributionS2SAuthenticationException exception)
        {
            return StatusCode(exception.StatusCode, new DistributionApiError(exception.ErrorCode));
        }
        catch (DistributionOperationException exception)
        {
            // TKT-004085: a named assignment refusal also publishes its bounded reason (and Retry-After when busy).
            AssignmentRefusals.ApplyRetryAfter(Response, exception.ErrorCode);
            return StatusCode(exception.StatusCode, new DistributionApiError(
                exception.ErrorCode, AssignmentRefusals.PublicReasonCode(exception.ErrorCode, exception.ReasonCode)));
        }
        catch (InvalidDataException)
        {
            return BadRequest(new DistributionApiError("invalid_request"));
        }
        catch (JsonException)
        {
            return BadRequest(new DistributionApiError("invalid_request"));
        }
        catch (Exception exception) when (!cancellationToken.IsCancellationRequested
            // TKT-004085: an assignment-trigger refusal is answered as its named code by ApiExceptionSafetyNetMiddleware.
            && !AssignmentRefusals.IsTriggerRefusal(exception))
        {
            return StatusCode(StatusCodes.Status500InternalServerError, new DistributionApiError("internal_error"));
        }
    }

    /// <summary>Authenticates exact finalize bytes and returns the committed binding or a bounded error; VM-policy refusals expose only their public code and message. A principal without <see cref="DistributionS2SPrincipal.MayDriveInstallation"/> gets 403 <c>installation_not_authorized</c> before any write (TKT-003162).</summary>
    /// <param name="cancellationToken">Cancels authentication or provider work before its transaction commits.</param>
    /// <returns>The binding, an inert exact replay, or a structured error without machine evidence.</returns>
    [HttpPost("/api/internal/v1/distribution-installation-bindings/finalize")]
    public async Task<IActionResult> FinalizeInstallation(CancellationToken cancellationToken)
    {
        try
        {
            var exactBody = await ReadExactBodyAsync(Request, cancellationToken);
            var productId = ExtractProductIdForAuthentication(exactBody);
            var principal = await _authentication.AuthenticateAndReserveNonceAsync(
                HttpContext, exactBody, productId, cancellationToken);
            if (!principal.MayDriveInstallation)
                return InstallationNotAuthorized();
            var request = Deserialize<DistributionInstallationFinalizeRequest>(exactBody);
            var result = await _bindings.FinalizeAsync(
                principal.ClientId, Digest(exactBody), request, cancellationToken);
            return StatusCode(result.Idempotent ? StatusCodes.Status200OK : StatusCodes.Status201Created, result.Response);
        }
        catch (DistributionS2SAuthenticationException exception)
        {
            return StatusCode(exception.StatusCode, new DistributionApiError(exception.ErrorCode));
        }
        catch (DistributionOperationException exception)
        {
            var policyMessage = VirtualMachinePolicy.Message(exception.ErrorCode);
            return StatusCode(exception.StatusCode, new DistributionApiError(exception.ErrorCode,
                policyMessage is null ? exception.ReasonCode : null, policyMessage));
        }
        catch (InvalidDataException)
        {
            return BadRequest(new DistributionApiError("invalid_request"));
        }
        catch (JsonException)
        {
            return BadRequest(new DistributionApiError("invalid_request"));
        }
        catch (Exception exception) when (!cancellationToken.IsCancellationRequested
            // TKT-004085: an assignment-trigger refusal is answered as its named code by ApiExceptionSafetyNetMiddleware.
            && !AssignmentRefusals.IsTriggerRefusal(exception))
        {
            return StatusCode(StatusCodes.Status500InternalServerError, new DistributionApiError("internal_error"));
        }
    }

    /// <summary>
    /// Invalidates, or replays idempotently, an installation binding owned by the authenticated distribution client.
    /// A principal without <see cref="DistributionS2SPrincipal.MayDriveInstallation"/> gets 403
    /// <c>installation_not_authorized</c> before any write (TKT-003162).
    /// </summary>
    /// <param name="cancellationToken">Cancels body reading, authentication, or provider work before commit.</param>
    /// <returns>201 for a new invalidation, 200 for an exact replay, or a bounded JSON error.</returns>
    [HttpPost("/api/internal/v1/distribution-installation-bindings/invalidate")]
    public async Task<IActionResult> InvalidateInstallation(CancellationToken cancellationToken)
    {
        try
        {
            var exactBody = await ReadExactBodyAsync(Request, cancellationToken);
            var productId = ExtractProductIdForAuthentication(exactBody);
            var principal = await _authentication.AuthenticateAndReserveNonceAsync(
                HttpContext, exactBody, productId, cancellationToken);
            if (!principal.MayDriveInstallation)
                return InstallationNotAuthorized();
            var request = Deserialize<DistributionInstallationInvalidationRequest>(exactBody);
            var result = await _bindings.InvalidateAsync(
                principal.ClientId, Digest(exactBody), request, cancellationToken);
            return StatusCode(result.Idempotent ? StatusCodes.Status200OK : StatusCodes.Status201Created, result.Response);
        }
        catch (DistributionS2SAuthenticationException exception)
        {
            return StatusCode(exception.StatusCode, new DistributionApiError(exception.ErrorCode));
        }
        catch (DistributionOperationException exception)
        {
            // TKT-004085: a named assignment refusal also publishes its bounded reason (and Retry-After when busy).
            AssignmentRefusals.ApplyRetryAfter(Response, exception.ErrorCode);
            return StatusCode(exception.StatusCode, new DistributionApiError(
                exception.ErrorCode, AssignmentRefusals.PublicReasonCode(exception.ErrorCode, exception.ReasonCode)));
        }
        catch (InvalidDataException)
        {
            return BadRequest(new DistributionApiError("invalid_request"));
        }
        catch (JsonException)
        {
            return BadRequest(new DistributionApiError("invalid_request"));
        }
        catch (Exception exception) when (!cancellationToken.IsCancellationRequested
            // TKT-004085: an assignment-trigger refusal is answered as its named code by ApiExceptionSafetyNetMiddleware.
            && !AssignmentRefusals.IsTriggerRefusal(exception))
        {
            return StatusCode(StatusCodes.Status500InternalServerError, new DistributionApiError("internal_error"));
        }
    }

    /// <summary>
    /// TKT-003162: answers 403 <c>installation_not_authorized</c> to an authenticated S2S principal that does not
    /// hold <see cref="DistributionS2SPrincipal.MayDriveInstallation"/>. Every route of this controller calls it
    /// right after authentication and before deserialization or any service call, so a dedicated identity
    /// (portal, key activation, account relink) gets no read, decision or write from these routes.
    /// </summary>
    /// <returns>The bounded 403 JSON error, without cause details.</returns>
    private ObjectResult InstallationNotAuthorized() =>
        StatusCode(StatusCodes.Status403Forbidden,
            new DistributionApiError(DistributionS2SPrincipal.InstallationNotAuthorizedErrorCode));

    private static async Task<byte[]> ReadExactBodyAsync(HttpRequest request, CancellationToken cancellationToken)
    {
        if (request.ContentLength is > MaximumBodyBytes or 0)
            throw new InvalidDataException();
        if (!MediaTypeHeaderValue.TryParse(request.ContentType, out var contentType)
            || !string.Equals(contentType.MediaType, "application/json", StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException();

        using var memory = new MemoryStream();
        var buffer = new byte[4096];
        while (true)
        {
            var read = await request.Body.ReadAsync(buffer, cancellationToken);
            if (read == 0)
                break;
            if (memory.Length + read > MaximumBodyBytes)
                throw new InvalidDataException();
            await memory.WriteAsync(buffer.AsMemory(0, read), cancellationToken);
        }
        if (memory.Length == 0)
            throw new InvalidDataException();
        return memory.ToArray();
    }

    private static string ExtractProductIdForAuthentication(ReadOnlyMemory<byte> exactBody)
    {
        using var document = JsonDocument.Parse(exactBody);
        if (document.RootElement.ValueKind != JsonValueKind.Object)
            throw new JsonException();

        string? productId = null;
        foreach (var property in document.RootElement.EnumerateObject())
        {
            if (property.Name == "productId" && property.Value.ValueKind == JsonValueKind.String)
            {
                if (productId != null)
                    throw new JsonException();
                productId = property.Value.GetString();
            }
        }
        return productId ?? throw new JsonException();
    }

    private static void ValidateNoDuplicateProperties(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            var seen = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in element.EnumerateObject())
            {
                if (!seen.Add(property.Name))
                    throw new JsonException();
                ValidateNoDuplicateProperties(property.Value);
            }
            return;
        }
        if (element.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in element.EnumerateArray())
                ValidateNoDuplicateProperties(item);
        }
    }

    private static T Deserialize<T>(ReadOnlyMemory<byte> exactBody) where T : class
    {
        using var document = JsonDocument.Parse(exactBody);
        ValidateNoDuplicateProperties(document.RootElement);
        return JsonSerializer.Deserialize<T>(exactBody.Span, RequestJsonOptions) ?? throw new JsonException();
    }

    private static string Digest(ReadOnlySpan<byte> exactBody) =>
        Convert.ToHexStringLower(SHA256.HashData(exactBody));
}
