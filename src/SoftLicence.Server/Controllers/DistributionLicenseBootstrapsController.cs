using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using SoftLicence.Server.Models;
using SoftLicence.Server.Services;

namespace SoftLicence.Server.Controllers;

[ApiController]
[EnableRateLimiting("DistributionS2SAPI")]
public sealed class DistributionLicenseBootstrapsController(
    IDistributionS2SAuthenticationService authentication,
    IDistributionLicenseBootstrapService bootstraps) : ControllerBase
{
    private const int MaximumBodyBytes = 4096;
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow
    };

    [HttpPost("/api/internal/v1/distribution-license-bootstraps/issue")]
    public Task<IActionResult> Issue(CancellationToken cancellationToken) =>
        ExecuteAsync("issue", cancellationToken);

    [HttpPost("/api/internal/v1/distribution-license-bootstraps/remint")]
    public Task<IActionResult> Remint(CancellationToken cancellationToken) =>
        ExecuteAsync("remint", cancellationToken);

    [HttpPost("/api/internal/v1/distribution-license-bootstraps/recover")]
    public Task<IActionResult> Recover(CancellationToken cancellationToken) =>
        ExecuteAsync("recover", cancellationToken);

    private async Task<IActionResult> ExecuteAsync(string operation, CancellationToken cancellationToken)
    {
        Response.Headers.CacheControl = "no-store";
        try
        {
            var expectedPath = operation switch
            {
                "issue" => "/api/internal/v1/distribution-license-bootstraps/issue",
                "remint" => "/api/internal/v1/distribution-license-bootstraps/remint",
                "recover" => "/api/internal/v1/distribution-license-bootstraps/recover",
                _ => throw new InvalidDataException()
            };
            if (Request.Path.Value != expectedPath || Request.QueryString.HasValue || Request.Headers.ContainsKey("Transfer-Encoding"))
                throw new InvalidDataException();
            var body = await ReadBodyAsync(Request, cancellationToken);
            var productId = ExtractUniqueString(body, "productId");
            var principal = await authentication.AuthenticateAndReserveNonceAsync(
                HttpContext, body, productId, cancellationToken);
            if (!principal.AllowLicenseBootstrap)
                return StatusCode(StatusCodes.Status403Forbidden, new DistributionApiError("license_bootstrap_forbidden"));
            var digest = Convert.ToHexStringLower(SHA256.HashData(body));
            DistributionLicenseBootstrapOperationResult<DistributionLicenseBootstrapIssuedResponse> result;
            if (operation == "remint")
                result = await bootstraps.RemintAsync(principal.ClientId, digest,
                    Deserialize<DistributionLicenseBootstrapRemintRequest>(body), cancellationToken);
            else if (operation == "recover")
                result = await bootstraps.RecoverAsync(principal.ClientId, digest,
                    Deserialize<DistributionLicenseBootstrapRecoverRequest>(body), cancellationToken);
            else
                result = await bootstraps.IssueAsync(principal.ClientId, digest,
                    Deserialize<DistributionLicenseBootstrapIssueRequest>(body), cancellationToken);
            Response.StatusCode = result.Idempotent ? StatusCodes.Status200OK : StatusCodes.Status201Created;
            return File(result.ExactResponseBody, "application/json");
        }
        catch (DistributionS2SAuthenticationException exception)
        {
            return StatusCode(exception.StatusCode, new DistributionApiError(exception.ErrorCode));
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

    private static async Task<byte[]> ReadBodyAsync(HttpRequest request, CancellationToken cancellationToken)
    {
        if (request.ContentLength is null or <= 0 or > MaximumBodyBytes
            || !MediaTypeHeaderValue.TryParse(request.ContentType, out var contentType)
            || !string.Equals(contentType.MediaType, "application/json", StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException();
        var bytes = new byte[request.ContentLength.Value];
        var offset = 0;
        while (offset < bytes.Length)
        {
            var read = await request.Body.ReadAsync(bytes.AsMemory(offset), cancellationToken);
            if (read == 0) throw new InvalidDataException();
            offset += read;
        }
        if (await request.Body.ReadAsync(new byte[1], cancellationToken) != 0)
            throw new InvalidDataException();
        return bytes;
    }

    private static T Deserialize<T>(byte[] body) where T : class
    {
        using var document = JsonDocument.Parse(body);
        ValidateUniqueProperties(document.RootElement);
        return JsonSerializer.Deserialize<T>(body, JsonOptions) ?? throw new JsonException();
    }

    private static string ExtractUniqueString(byte[] body, string name)
    {
        using var document = JsonDocument.Parse(body);
        ValidateUniqueProperties(document.RootElement);
        string? value = null;
        foreach (var property in document.RootElement.EnumerateObject())
            if (property.Name == name && property.Value.ValueKind == JsonValueKind.String)
            {
                if (value != null) throw new JsonException();
                value = property.Value.GetString();
            }
        return value ?? throw new JsonException();
    }

    private static void ValidateUniqueProperties(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in element.EnumerateObject())
            {
                if (!names.Add(property.Name)) throw new JsonException();
                ValidateUniqueProperties(property.Value);
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
            foreach (var item in element.EnumerateArray()) ValidateUniqueProperties(item);
    }
}
