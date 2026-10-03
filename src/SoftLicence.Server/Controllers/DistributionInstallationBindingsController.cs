using System.Security.Cryptography;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using SoftLicence.Server.Models;
using SoftLicence.Server.Services;

namespace SoftLicence.Server.Controllers;

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
        catch (Exception) when (!cancellationToken.IsCancellationRequested)
        {
            return StatusCode(StatusCodes.Status500InternalServerError, new DistributionApiError("internal_error"));
        }
    }

    /// <summary>
    /// Authenticates the exact request bytes, reserves the S2S nonce, and evaluates server-owned
    /// machine authority before any payload lease is issued. Responses and middleware logs exclude
    /// raw observations; malformed, banned, or unavailable authority fails closed.
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
            // TKT-001277: a UUID refusal exposes only its customer support code (AR-xx); every other denial
            // stays opaque.
            return StatusCode(exception.StatusCode, new DistributionApiError(exception.ErrorCode,
                exception.ErrorCode == RuntimeDistributionPreflightService.DeviceRefusedErrorCode ? exception.ReasonCode : null));
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

    /// <summary>Resolves the bounded Runtime source authority for Website Finalize construction.</summary>
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
        catch (Exception) when (!cancellationToken.IsCancellationRequested)
        {
            return StatusCode(StatusCodes.Status500InternalServerError, new DistributionApiError("internal_error"));
        }
    }

    [HttpPost("/api/internal/v1/distribution-entitlements/issue")]
    public async Task<IActionResult> IssueEntitlement(CancellationToken cancellationToken)
    {
        try
        {
            var exactBody = await ReadExactBodyAsync(Request, cancellationToken);
            var productId = ExtractProductIdForAuthentication(exactBody);
            var principal = await _authentication.AuthenticateAndReserveNonceAsync(
                HttpContext, exactBody, productId, cancellationToken);
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
            return StatusCode(exception.StatusCode, new DistributionApiError(exception.ErrorCode));
        }
        catch (InvalidDataException)
        {
            return BadRequest(new DistributionApiError("invalid_request"));
        }
        catch (JsonException)
        {
            return BadRequest(new DistributionApiError("invalid_request"));
        }
        catch (Exception) when (!cancellationToken.IsCancellationRequested)
        {
            return StatusCode(StatusCodes.Status500InternalServerError, new DistributionApiError("internal_error"));
        }
    }

    [HttpPost("/api/internal/v1/distribution-installation-bindings/finalize")]
    public async Task<IActionResult> FinalizeInstallation(CancellationToken cancellationToken)
    {
        try
        {
            var exactBody = await ReadExactBodyAsync(Request, cancellationToken);
            var productId = ExtractProductIdForAuthentication(exactBody);
            var principal = await _authentication.AuthenticateAndReserveNonceAsync(
                HttpContext, exactBody, productId, cancellationToken);
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
        catch (Exception) when (!cancellationToken.IsCancellationRequested)
        {
            return StatusCode(StatusCodes.Status500InternalServerError, new DistributionApiError("internal_error"));
        }
    }

    [HttpPost("/api/internal/v1/distribution-installation-bindings/invalidate")]
    public async Task<IActionResult> InvalidateInstallation(CancellationToken cancellationToken)
    {
        try
        {
            var exactBody = await ReadExactBodyAsync(Request, cancellationToken);
            var productId = ExtractProductIdForAuthentication(exactBody);
            var principal = await _authentication.AuthenticateAndReserveNonceAsync(
                HttpContext, exactBody, productId, cancellationToken);
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
            return StatusCode(exception.StatusCode, new DistributionApiError(exception.ErrorCode));
        }
        catch (InvalidDataException)
        {
            return BadRequest(new DistributionApiError("invalid_request"));
        }
        catch (JsonException)
        {
            return BadRequest(new DistributionApiError("invalid_request"));
        }
        catch (Exception) when (!cancellationToken.IsCancellationRequested)
        {
            return StatusCode(StatusCodes.Status500InternalServerError, new DistributionApiError("internal_error"));
        }
    }

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
