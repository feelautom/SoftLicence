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
/// Exposes the sole provider-owned portal-deactivation route behind Distribution S2S authentication.
/// </summary>
[ApiController]
[EnableRateLimiting("DistributionS2SAPI")]
public sealed class PortalDeactivationsController : ControllerBase
{
    private const int MaximumBodyBytes = 4096;
    private const string CorrelationHeader = "X-Correlation-Id";
    private static readonly JsonSerializerOptions RequestJsonOptions = new(JsonSerializerDefaults.Web)
    {
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow
    };

    private readonly IDistributionS2SAuthenticationService _authentication;
    private readonly IPortalDeactivationService _deactivations;

    /// <summary>Initializes the controller with authentication and provider mutation boundaries.</summary>
    public PortalDeactivationsController(
        IDistributionS2SAuthenticationService authentication,
        IPortalDeactivationService deactivations)
    {
        _authentication = authentication;
        _deactivations = deactivations;
    }

    /// <summary>
    /// Authenticates exact request bytes before applying any five-minute deactivation bypass.
    /// </summary>
    /// <param name="cancellationToken">Cancels body reading, authentication, or database work before commit.</param>
    /// <returns>A bounded HTTP 200 terminal result, or a stable fail-closed API error.</returns>
    [HttpPost("/api/internal/v1/portal-deactivations")]
    public async Task<IActionResult> Deactivate(CancellationToken cancellationToken)
    {
        try
        {
            var exactBody = await ReadExactBodyAsync(Request, cancellationToken);
            var productId = ExtractProductIdForAuthentication(exactBody);
            var principal = await _authentication.AuthenticateAndReserveNonceAsync(
                HttpContext,
                exactBody,
                productId,
                cancellationToken);
            if (!principal.AllowPortalDeactivation)
                return StatusCode(StatusCodes.Status403Forbidden, new DistributionApiError("capability_denied"));

            var request = Deserialize(exactBody);
            EnsureStableCorrelation(Request, request.RequestId);
            var result = await _deactivations.DeactivateAsync(
                principal.ClientId,
                Digest(exactBody),
                request,
                cancellationToken);
            return Ok(result.Response);
        }
        catch (DistributionS2SAuthenticationException exception)
        {
            return StatusCode(exception.StatusCode, new DistributionApiError(exception.ErrorCode));
        }
        catch (PortalDeactivationQuotaException exception)
        {
            return StatusCode(StatusCodes.Status429TooManyRequests, exception.Refusal);
        }
        catch (DistributionOperationException exception)
        {
            return StatusCode(exception.StatusCode, new DistributionApiError(exception.ErrorCode));
        }
        catch (Exception exception) when (exception is InvalidDataException or JsonException)
        {
            return BadRequest(new DistributionApiError("invalid_request"));
        }
        catch (Exception) when (!cancellationToken.IsCancellationRequested)
        {
            return StatusCode(StatusCodes.Status500InternalServerError, new DistributionApiError("internal_error"));
        }
    }

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

    private static PortalDeactivationRequest Deserialize(ReadOnlyMemory<byte> exactBody)
    {
        using var document = JsonDocument.Parse(exactBody);
        ValidateNoDuplicateProperties(document.RootElement);
        return JsonSerializer.Deserialize<PortalDeactivationRequest>(exactBody.Span, RequestJsonOptions)
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
