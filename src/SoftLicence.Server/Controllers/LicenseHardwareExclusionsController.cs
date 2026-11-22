using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using SoftLicence.Server.Models;
using SoftLicence.Server.Services;

namespace SoftLicence.Server.Controllers;

/// <summary>
/// Exposes the provider-owned licence hardware exclusion routes behind Distribution S2S
/// authentication. Exclusions are licence-scoped commercial admission refusals, never security
/// bans: the machine stays free for every other licence and product.
/// </summary>
[ApiController]
[EnableRateLimiting("DistributionS2SAPI")]
public sealed class LicenseHardwareExclusionsController : ControllerBase
{
    private const int MaximumBodyBytes = 4096;
    private const string CorrelationHeader = "X-Correlation-Id";
    private static readonly JsonSerializerOptions RequestJsonOptions = new(JsonSerializerDefaults.Web)
    {
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow
    };

    private readonly IDistributionS2SAuthenticationService _authentication;
    private readonly ILicenseHardwareExclusionService _exclusions;

    /// <summary>Initializes the controller with authentication and the provider mutation service.</summary>
    public LicenseHardwareExclusionsController(
        IDistributionS2SAuthenticationService authentication,
        ILicenseHardwareExclusionService exclusions)
    {
        _authentication = authentication;
        _exclusions = exclusions;
    }

    /// <summary>
    /// Applies one exclusion, optionally releasing the active seat inside the same transaction.
    /// </summary>
    /// <param name="cancellationToken">Cancels body reading, authentication, or database work before commit.</param>
    /// <returns>A bounded HTTP 200 terminal result, or a stable fail-closed API error.</returns>
    [HttpPost("/api/internal/v1/license-hardware-exclusions")]
    public async Task<IActionResult> Add(CancellationToken cancellationToken)
    {
        try
        {
            var result = await ExecuteAsync(cancellationToken);
            return Ok(result.Response);
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
        catch (Exception exception) when (exception is InvalidDataException or JsonException)
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

    /// <summary>Lifts one active exclusion without reactivating anything.</summary>
    /// <param name="cancellationToken">Cancels body reading, authentication, or database work before commit.</param>
    /// <returns>A bounded HTTP 200 terminal result, or a stable fail-closed API error.</returns>
    [HttpPost("/api/internal/v1/license-hardware-exclusions/lift")]
    public async Task<IActionResult> Lift(CancellationToken cancellationToken)
    {
        try
        {
            var response = await ExecuteLiftAsync(
                LicenseHardwareExclusionService.S2SActor,
                cancellationToken);
            return Ok(response);
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
        catch (Exception exception) when (exception is InvalidDataException or JsonException)
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

    /// <summary>Returns a bounded list of the exclusions of one licence; no write occurs.</summary>
    /// <param name="cancellationToken">Cancels body reading, authentication, or database work.</param>
    /// <returns>A bounded HTTP 200 list page, or a stable fail-closed API error.</returns>
    [HttpPost("/api/internal/v1/license-hardware-exclusions/list")]
    public async Task<IActionResult> List(CancellationToken cancellationToken)
    {
        try
        {
            var response = await ExecuteListAsync(cancellationToken);
            return Ok(response);
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
        catch (Exception exception) when (exception is InvalidDataException or JsonException)
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

    private async Task<LicenseHardwareExclusionResult> ExecuteAsync(CancellationToken cancellationToken)
    {
        var exactBody = await ReadExactBodyAsync(Request, cancellationToken);
        var productId = ExtractProductIdForAuthentication(exactBody);
        var principal = await _authentication.AuthenticateAndReserveNonceAsync(
            HttpContext, exactBody, productId, cancellationToken);
        if (!principal.AllowLicenseHardwareExclusions)
            return DenyCapability<LicenseHardwareExclusionResult>();

        var request = Deserialize<LicenseHardwareExclusionRequest>(exactBody);
        EnsureStableCorrelation(Request, request.RequestId);
        return await _exclusions.AddAsync(
            principal.ClientId,
            Digest(exactBody),
            request,
            cancellationToken);
    }

    private async Task<LicenseHardwareExclusionLiftResponse> ExecuteLiftAsync(
        string actor,
        CancellationToken cancellationToken)
    {
        var exactBody = await ReadExactBodyAsync(Request, cancellationToken);
        var productId = ExtractProductIdForAuthentication(exactBody);
        var principal = await _authentication.AuthenticateAndReserveNonceAsync(
            HttpContext, exactBody, productId, cancellationToken);
        if (!principal.AllowLicenseHardwareExclusions)
            return DenyCapability<LicenseHardwareExclusionLiftResponse>();

        var request = Deserialize<LicenseHardwareExclusionLiftRequest>(exactBody);
        EnsureStableCorrelation(Request, request.RequestId);
        return await _exclusions.LiftAsync(
            actor,
            principal.ClientId,
            request,
            cancellationToken);
    }

    private async Task<LicenseHardwareExclusionListResponse> ExecuteListAsync(
        CancellationToken cancellationToken)
    {
        var exactBody = await ReadExactBodyAsync(Request, cancellationToken);
        var productId = ExtractProductIdForAuthentication(exactBody);
        var principal = await _authentication.AuthenticateAndReserveNonceAsync(
            HttpContext, exactBody, productId, cancellationToken);
        if (!principal.AllowLicenseHardwareExclusions)
            return DenyCapability<LicenseHardwareExclusionListResponse>();

        var request = Deserialize<LicenseHardwareExclusionListRequest>(exactBody);
        EnsureStableCorrelation(Request, request.RequestId);
        return await _exclusions.ListAsync(request, cancellationToken);
    }

    private static T DenyCapability<T>()
        => throw new DistributionOperationException("capability_denied", StatusCodes.Status403Forbidden);

    private static async Task<byte[]> ReadExactBodyAsync(
        HttpRequest request,
        CancellationToken cancellationToken)
    {
        if (request.ContentLength is > MaximumBodyBytes or 0)
            throw new InvalidDataException();
        if (!MediaTypeHeaderValue.TryParse(request.ContentType, out var contentType)
            || !string.Equals(contentType.MediaType, "application/json", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException();
        }

        using var memory = new MemoryStream();
        var buffer = new byte[1024];
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
            if (!string.Equals(property.Name, "productId", StringComparison.Ordinal)
                || property.Value.ValueKind != JsonValueKind.String)
            {
                continue;
            }
            if (productId != null)
                throw new JsonException();
            productId = property.Value.GetString();
        }
        return productId ?? throw new JsonException();
    }

    private static T Deserialize<T>(ReadOnlyMemory<byte> exactBody)
    {
        using var document = JsonDocument.Parse(exactBody);
        ValidateNoDuplicateProperties(document.RootElement);
        return JsonSerializer.Deserialize<T>(exactBody.Span, RequestJsonOptions)
            ?? throw new JsonException();
    }

    private static void EnsureStableCorrelation(HttpRequest request, string? requestId)
    {
        var values = request.Headers[CorrelationHeader];
        if (values.Count != 1
            || requestId == null
            || !string.Equals(values[0], requestId, StringComparison.Ordinal))
        {
            throw new InvalidDataException();
        }
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

    private static string Digest(ReadOnlySpan<byte> exactBody) =>
        Convert.ToHexStringLower(SHA256.HashData(exactBody));
}
