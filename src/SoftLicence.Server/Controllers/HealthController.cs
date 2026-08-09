using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using SoftLicence.Server.Data;
using SoftLicence.Server.Models;
using SoftLicence.Server.Services;

namespace SoftLicence.Server.Controllers;

[ApiController]
[Route("api/health")]
[EnableRateLimiting("TelemetryAPI")]
public sealed class HealthController : ControllerBase
{
    private const int MaximumBodyBytes = 4096;
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private static readonly string[] CanaryAckRequestFields =
    [
        "schema", "eventId", "sentAtUtc", "hardwareId", "appVersion", "trigger", "severity"
    ];
    private static readonly JsonSerializerOptions RequestJsonOptions = new(JsonSerializerDefaults.Web)
    {
        PropertyNameCaseInsensitive = false
    };

    private readonly ILogger<HealthController> _logger;
    private readonly CanaryAckService? _canaryAck;
    private readonly IRuntimeEnrollmentService? _runtimeEnrollments;

    public HealthController(
        ILogger<HealthController> logger,
        CanaryAckService? canaryAck = null,
        IRuntimeEnrollmentService? runtimeEnrollments = null)
    {
        _logger = logger;
        _canaryAck = canaryAck;
        _runtimeEnrollments = runtimeEnrollments;
    }

    [HttpPost("ping")]
    public async Task<IActionResult> Ping(CancellationToken cancellationToken)
    {
        SetNoStore();
        try
        {
            EnsureExactTarget();
            var exactBody = await ReadStrictBodyAsync(Request, cancellationToken);
            using var document = JsonDocument.Parse(exactBody);
            return await ProcessExactAsync(document.RootElement, exactBody, cancellationToken);
        }
        catch (CanaryTransportException exception)
        {
            return StatusCode(exception.StatusCode, new { error = exception.ErrorCode });
        }
        catch (Exception exception) when (exception is JsonException or DecoderFallbackException)
        {
            return BadRequest(new { error = "invalid_request" });
        }
    }

    [NonAction]
    public Task<IActionResult> Ping(JsonElement payload, CancellationToken cancellationToken = default)
    {
        var exactBody = Encoding.UTF8.GetBytes(payload.GetRawText());
        return ProcessExactAsync(payload, exactBody, cancellationToken);
    }

    [NonAction]
    public Task<IActionResult> Ping(CanaryPingRequest? request, CancellationToken cancellationToken = default)
    {
        if (request == null)
            return Task.FromResult<IActionResult>(BadRequest(new { error = "invalid_request" }));
        var exactBody = JsonSerializer.SerializeToUtf8Bytes(request, RequestJsonOptions);
        using var document = JsonDocument.Parse(exactBody);
        return ProcessExactAsync(document.RootElement.Clone(), exactBody, cancellationToken);
    }

    private async Task<IActionResult> ProcessExactAsync(
        JsonElement payload,
        ReadOnlyMemory<byte> exactBody,
        CancellationToken cancellationToken)
    {
        if (!TryDeserializeCritical(payload, out var request))
        {
            _logger.LogInformation("Unauthenticated canary input ignored without durable effect");
            return Accepted(new { status = "ignored" });
        }
        if (_canaryAck == null || _runtimeEnrollments == null)
            return StatusCode(StatusCodes.Status503ServiceUnavailable, new { error = "canary_authority_unavailable" });

        try
        {
            var enrollmentIdValue = ReadSingletonHeader("X-Runtime-Enrollment-Id");
            if (!TryCanonicalUuid(enrollmentIdValue, out var enrollmentId))
                throw new RuntimeEnrollmentException("authentication_failed", StatusCodes.Status401Unauthorized);
            var proof = new RuntimeProofHeaders(
                ReadSingletonHeader("X-Runtime-Enrollment-Timestamp"),
                ReadSingletonHeader("X-Runtime-Enrollment-Jti"),
                ReadSingletonHeader("X-Runtime-Enrollment-Signature"));
            var result = await _runtimeEnrollments.ProcessCanaryAsync(
                enrollmentId, Digest(exactBody.Span), request!, proof,
                HttpContext.Connection.RemoteIpAddress, cancellationToken);
            return File(result.ExactResponseBody, "application/json");
        }
        catch (CanaryAckValidationException exception)
        {
            _logger.LogWarning("Canary request rejected before persistence: {ErrorCode}", exception.ErrorCode);
            return BadRequest(new { error = "invalid_request" });
        }
        catch (RuntimeEnrollmentException exception)
        {
            _logger.LogWarning("Canary proof rejected before durable effect: {ErrorCode}", exception.ErrorCode);
            return StatusCode(exception.StatusCode, new { error = exception.ErrorCode });
        }
        catch (CanaryAckConfigurationException)
        {
            return StatusCode(StatusCodes.Status503ServiceUnavailable, new { error = "ack_unavailable" });
        }
    }

    [HttpGet("canary-keys/{keyId}")]
    public IActionResult GetCanaryPublicKey(string keyId)
    {
        if (_canaryAck == null)
            return StatusCode(StatusCodes.Status503ServiceUnavailable, new { error = "ack_unavailable" });
        try
        {
            return _canaryAck.TryGetPublicKey(keyId, out var response)
                ? Ok(response)
                : NotFound();
        }
        catch (CanaryAckConfigurationException)
        {
            return StatusCode(StatusCodes.Status503ServiceUnavailable, new { error = "ack_unavailable" });
        }
    }

    private void EnsureExactTarget()
    {
        if (!string.Equals(Request.Method, HttpMethods.Post, StringComparison.Ordinal)
            || !string.Equals(Request.Path.Value, "/api/health/ping", StringComparison.Ordinal)
            || Request.QueryString.HasValue
            || Request.Headers.ContainsKey("Transfer-Encoding")
            || Request.Headers.ContainsKey("Content-Encoding"))
            throw new CanaryTransportException(StatusCodes.Status400BadRequest, "invalid_request");
    }

    private static async Task<ReadOnlyMemory<byte>> ReadStrictBodyAsync(
        HttpRequest request,
        CancellationToken cancellationToken)
    {
        if (request.ContentLength is null or <= 0)
            throw new CanaryTransportException(StatusCodes.Status400BadRequest, "invalid_request");
        if (request.ContentLength > MaximumBodyBytes)
            throw new CanaryTransportException(StatusCodes.Status413PayloadTooLarge, "payload_too_large");
        if (!MediaTypeHeaderValue.TryParse(request.ContentType, out var mediaType)
            || !string.Equals(mediaType.MediaType, "application/json", StringComparison.OrdinalIgnoreCase)
            || mediaType.Parameters.Count > 1
            || mediaType.Parameters.Any(parameter =>
                !string.Equals(parameter.Name, "charset", StringComparison.OrdinalIgnoreCase)
                || !string.Equals(parameter.Value?.Trim('"'), "utf-8", StringComparison.OrdinalIgnoreCase)))
            throw new CanaryTransportException(StatusCodes.Status415UnsupportedMediaType, "unsupported_media_type");

        var bytes = new byte[checked((int)request.ContentLength.Value)];
        var offset = 0;
        while (offset < bytes.Length)
        {
            var read = await request.Body.ReadAsync(bytes.AsMemory(offset), cancellationToken);
            if (read == 0)
                throw new CanaryTransportException(StatusCodes.Status400BadRequest, "invalid_request");
            offset += read;
        }
        if (await request.Body.ReadAsync(new byte[1], cancellationToken) != 0
            || bytes.AsSpan().StartsWith(Encoding.UTF8.Preamble))
            throw new CanaryTransportException(StatusCodes.Status400BadRequest, "invalid_request");
        _ = StrictUtf8.GetString(bytes);
        return bytes;
    }

    private static bool TryDeserializeCritical(JsonElement payload, out CanaryPingRequest? request)
    {
        request = null;
        if (payload.ValueKind != JsonValueKind.Object)
            return false;
        var properties = payload.EnumerateObject().ToList();
        if (properties.Count != CanaryAckRequestFields.Length)
            return false;
        var names = properties.Select(property => property.Name).ToHashSet(StringComparer.Ordinal);
        if (names.Count != CanaryAckRequestFields.Length
            || CanaryAckRequestFields.Any(field => !names.Contains(field)))
            return false;
        try
        {
            request = payload.Deserialize<CanaryPingRequest>(RequestJsonOptions);
            return request?.Schema == CanaryAckService.Schema;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private string ReadSingletonHeader(string name)
    {
        if (!Request.Headers.TryGetValue(name, out var values) || values.Count != 1)
            throw new RuntimeEnrollmentException("authentication_failed", StatusCodes.Status401Unauthorized);
        var value = values[0] ?? string.Empty;
        if (value.Length == 0 || value.Contains(',') || value.Any(char.IsControl))
            throw new RuntimeEnrollmentException("authentication_failed", StatusCodes.Status401Unauthorized);
        return value;
    }

    private static bool TryCanonicalUuid(string value, out Guid parsed)
    {
        parsed = default;
        return Guid.TryParseExact(value, "D", out parsed) && value == parsed.ToString("D");
    }

    private static string Digest(ReadOnlySpan<byte> body) =>
        Convert.ToHexStringLower(SHA256.HashData(body));

    private void SetNoStore()
    {
        Response.Headers.CacheControl = "no-store, max-age=0";
        Response.Headers.Pragma = "no-cache";
    }

    private sealed class CanaryTransportException(int statusCode, string errorCode) : Exception(errorCode)
    {
        public int StatusCode { get; } = statusCode;
        public string ErrorCode { get; } = errorCode;
    }
}
