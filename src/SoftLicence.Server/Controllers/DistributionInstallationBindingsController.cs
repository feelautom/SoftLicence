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

    public DistributionInstallationBindingsController(
        IDistributionS2SAuthenticationService authentication,
        IDistributionInstallationBindingService bindings)
    {
        _authentication = authentication;
        _bindings = bindings;
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
